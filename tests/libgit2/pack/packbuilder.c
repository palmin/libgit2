#include "clar_libgit2.h"
#include "futils.h"
#include "pack.h"
#include "pack-objects.h"
#include "odb.h"
#include "hash.h"
#include "iterator.h"
#include "vector.h"
#include "posix.h"
#include "hash.h"

static git_repository *_repo;
static git_revwalk *_revwalker;
static git_packbuilder *_packbuilder;
static git_indexer *_indexer;
static git_vector _commits;
static int _commits_is_initialized;
static git_indexer_progress _stats;

extern bool git_disable_pack_keep_file_checks;

void test_pack_packbuilder__initialize(void)
{
	_repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(p_chdir("testrepo.git"));
	cl_git_pass(git_revwalk_new(&_revwalker, _repo));
	cl_git_pass(git_packbuilder_new(&_packbuilder, _repo));
	cl_git_pass(git_vector_init(&_commits, 0, NULL));
	_commits_is_initialized = 1;
	memset(&_stats, 0, sizeof(_stats));
	p_fsync__cnt = 0;
}

void test_pack_packbuilder__cleanup(void)
{
	git_oid *o;
	unsigned int i;

	cl_git_pass(git_libgit2_opts(GIT_OPT_ENABLE_FSYNC_GITDIR, 0));
	cl_git_pass(git_libgit2_opts(GIT_OPT_DISABLE_PACK_KEEP_FILE_CHECKS, false));

	if (_commits_is_initialized) {
		_commits_is_initialized = 0;
		git_vector_foreach(&_commits, i, o) {
			git__free(o);
		}
		git_vector_dispose(&_commits);
	}

	git_packbuilder_free(_packbuilder);
	_packbuilder = NULL;

	git_revwalk_free(_revwalker);
	_revwalker = NULL;

	git_indexer_free(_indexer);
	_indexer = NULL;

	cl_git_pass(p_chdir(".."));
	cl_git_sandbox_cleanup();
	_repo = NULL;
}

static void seed_packbuilder(void)
{
	git_oid oid, *o;
	unsigned int i;

	git_revwalk_sorting(_revwalker, GIT_SORT_TIME);
	cl_git_pass(git_revwalk_push_ref(_revwalker, "HEAD"));

	while (git_revwalk_next(&oid, _revwalker) == 0) {
		o = git__malloc(sizeof(git_oid));
		cl_assert(o != NULL);
		git_oid_cpy(o, &oid);
		cl_git_pass(git_vector_insert(&_commits, o));
	}

	git_vector_foreach(&_commits, i, o) {
		cl_git_pass(git_packbuilder_insert(_packbuilder, o, NULL));
	}

	git_vector_foreach(&_commits, i, o) {
		git_object *obj;
		cl_git_pass(git_object_lookup(&obj, _repo, o, GIT_OBJECT_COMMIT));
		cl_git_pass(git_packbuilder_insert_tree(_packbuilder,
					git_commit_tree_id((git_commit *)obj)));
		git_object_free(obj);
	}
}

static int feed_indexer(void *ptr, size_t len, void *payload)
{
	git_indexer_progress *stats = (git_indexer_progress *)payload;

	return git_indexer_append(_indexer, ptr, len, stats);
}

void test_pack_packbuilder__create_pack(void)
{
	git_indexer_progress stats;
	git_str buf = GIT_STR_INIT, path = GIT_STR_INIT;

	seed_packbuilder();

#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_indexer_new(&_indexer, ".", NULL));
#else
	cl_git_pass(git_indexer_new(&_indexer, ".", 0, NULL, NULL));
#endif

	cl_git_pass(git_packbuilder_foreach(_packbuilder, feed_indexer, &stats));
	cl_git_pass(git_indexer_commit(_indexer, &stats));

	git_str_printf(&path, "pack-%s.pack", git_indexer_name(_indexer));
	cl_assert(git_fs_path_exists(path.ptr));

	cl_git_pass(git_futils_readbuffer(&buf, git_str_cstr(&path)));
	cl_assert(buf.size > 256);

	git_str_dispose(&path);
	git_str_dispose(&buf);
}

void test_pack_packbuilder__get_name(void)
{
	seed_packbuilder();

	cl_git_pass(git_packbuilder_write(_packbuilder, ".", 0, NULL, NULL));
	cl_assert(git_packbuilder_name(_packbuilder) != NULL);
}

static void get_packfile_path(git_str *out, git_packbuilder *pb)
{
	git_str_puts(out, "pack-");
	git_str_puts(out, git_packbuilder_name(pb));
	git_str_puts(out, ".pack");
}

static void get_index_path(git_str *out, git_packbuilder *pb)
{
	git_str_puts(out, "pack-");
	git_str_puts(out, git_packbuilder_name(pb));
	git_str_puts(out, ".idx");
}

/*
 * Write the seeded objects to a pack and read every one back from that pack
 * alone, checking each hashes to its id, which a reused delta not rebuilding
 * its object would fail.
 */
static void write_and_verify(git_packbuilder *pb)
{
	git_odb *odb;
	git_odb_backend *backend;
	git_str idx = GIT_STR_INIT;
	size_t i;

	cl_git_pass(git_packbuilder_write(pb, ".", 0, NULL, NULL));
	get_index_path(&idx, pb);

	cl_git_pass(git_odb__new(&odb, NULL));
#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_odb_backend_one_pack(&backend, idx.ptr, NULL));
#else
	cl_git_pass(git_odb_backend_one_pack(&backend, idx.ptr));
#endif
	cl_git_pass(git_odb_add_backend(odb, backend, 1));

	for (i = 0; i < pb->nr_objects; i++) {
		git_pobject *po = pb->object_list + i;
		git_odb_object *obj;
		git_oid hashed;

		cl_git_pass(git_odb_read(&obj, odb, &po->id));
		cl_git_pass(git_odb__hash(&hashed, git_odb_object_data(obj),
			git_odb_object_size(obj), git_odb_object_type(obj), GIT_OID_SHA1));
		cl_assert_equal_oid(&po->id, &hashed);
		git_odb_object_free(obj);
	}

	git_odb_free(odb);
	git_str_dispose(&idx);
}

static void write_and_verify_pack(void)
{
	write_and_verify(_packbuilder);
}

static int insert_object(const git_oid *id, void *payload)
{
	GIT_UNUSED(payload);
	return git_packbuilder_insert(_packbuilder, id, NULL);
}

/*
 * Every object in the largest pack of testrepo.git, where most are stored as
 * deltas. The history of HEAD is all loose objects, and some loose objects
 * are malformed on purpose for other tests.
 */
static void seed_every_object(void)
{
	git_odb *odb;
	git_odb_backend *backend;

	cl_git_pass(git_odb__new(&odb, NULL));
#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_odb_backend_one_pack(&backend,
		"objects/pack/pack-a81e489679b7d3418f9ab594bda8ceb37dd4c695.idx", NULL));
#else
	cl_git_pass(git_odb_backend_one_pack(&backend,
		"objects/pack/pack-a81e489679b7d3418f9ab594bda8ceb37dd4c695.idx"));
#endif
	cl_git_pass(git_odb_add_backend(odb, backend, 1));
	cl_git_pass(git_odb_foreach(odb, insert_object, NULL));
	git_odb_free(odb);
}

void test_pack_packbuilder__reuses_deltas(void)
{
	seed_every_object();
	write_and_verify_pack();

	/* the packs of testrepo.git store some of these objects as deltas */
	cl_assert(git_packbuilder__reused_count(_packbuilder) > 0);
}

void test_pack_packbuilder__can_compute_every_delta(void)
{
	git_packbuilder_set_reuse_delta(_packbuilder, 0);
	seed_every_object();
	write_and_verify_pack();

	cl_assert_equal_i(0, git_packbuilder__reused_count(_packbuilder));
}

void test_pack_packbuilder__can_skip_delta_search(void)
{
	git_packbuilder_set_delta_search(_packbuilder, 0);
	seed_every_object();
	write_and_verify_pack();

	/* stored deltas are still reused, and nothing goes through the search */
	cl_assert(git_packbuilder__reused_count(_packbuilder) > 0);
	cl_assert_equal_i(0, _packbuilder->nr_deltified);
	cl_assert_equal_i(0, git_packbuilder__copied_count(_packbuilder));
}

void test_pack_packbuilder__copies_compressed_objects(void)
{
	git_packbuilder_set_delta_search(_packbuilder, 0);
	git_packbuilder_set_copy_compressed(_packbuilder, 1);
	seed_every_object();
	write_and_verify_pack();

	/* every object of a single pack is stored whole or as a delta on another */
	cl_assert(git_packbuilder__reused_count(_packbuilder) > 0);
	cl_assert_equal_i(_packbuilder->nr_objects, git_packbuilder__copied_count(_packbuilder));
}

void test_pack_packbuilder__copies_compressed_objects_with_delta_search(void)
{
	git_packbuilder_set_copy_compressed(_packbuilder, 1);
	seed_every_object();
	write_and_verify_pack();

	/* an object given a new delta is compressed, the rest copied */
	cl_assert(git_packbuilder__copied_count(_packbuilder) > 0);
	cl_assert(git_packbuilder__copied_count(_packbuilder) <= _packbuilder->nr_objects);
}

void test_pack_packbuilder__copies_whole_objects_without_reusing_deltas(void)
{
	git_packbuilder_set_reuse_delta(_packbuilder, 0);
	git_packbuilder_set_delta_search(_packbuilder, 0);
	git_packbuilder_set_copy_compressed(_packbuilder, 1);
	seed_every_object();
	write_and_verify_pack();

	/* objects stored as deltas are written whole, compressed again */
	cl_assert_equal_i(0, git_packbuilder__reused_count(_packbuilder));
	cl_assert(git_packbuilder__copied_count(_packbuilder) > 0);
	cl_assert(git_packbuilder__copied_count(_packbuilder) < _packbuilder->nr_objects);
}

/*
 * An object stored in several packs is found in one of them, so a delta can
 * find its base in another pack. Here the base is also stored whole in a
 * newer pack, along with an object only it has, which is looked up first, so
 * the odb looks for the base in that pack before any other. The delta is
 * reused all the same, as it is written against the id of its base.
 */
void test_pack_packbuilder__reuses_deltas_whose_base_is_in_another_pack(void)
{
	git_repository *repo;
	git_packbuilder *pb;
	git_odb *odb;
	git_str text = GIT_STR_INIT, path = GIT_STR_INIT;
	struct p_timeval times[2];
	git_oid first, second, other, base, delta;
	git_pobject *po = NULL;
	size_t i;

	cl_git_pass(git_repository_init(&repo, "elsewhere.git", 1));

	/* two similar blobs, so one is stored as a delta on the other */
	for (i = 0; i < 100; i++)
		git_str_printf(&text, "line %d of a file long enough to be worth a delta\n", (int)i);
	cl_git_pass(git_blob_create_from_buffer(&first, repo, text.ptr, text.size));
	git_str_puts(&text, "and one more line\n");
	cl_git_pass(git_blob_create_from_buffer(&second, repo, text.ptr, text.size));
	cl_git_pass(git_blob_create_from_buffer(&other, repo, "something else\n", 15));
	git_str_dispose(&text);

	cl_git_pass(git_packbuilder_new(&pb, repo));
	cl_git_pass(git_packbuilder_insert(pb, &first, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &second, NULL));
	cl_git_pass(git_packbuilder_write(pb, "elsewhere.git/objects/pack", 0, NULL, NULL));
	for (i = 0; i < pb->nr_objects; i++) {
		if (pb->object_list[i].delta)
			po = pb->object_list + i;
	}
	cl_assert(po != NULL);
	git_oid_cpy(&delta, &po->id);
	git_oid_cpy(&base, &po->delta->id);
	git_packbuilder_free(pb);

	/* packs are searched newest first, and both were written this second */
	cl_git_pass(git_packbuilder_new(&pb, repo));
	git_packbuilder_set_reuse_delta(pb, 0);
	git_packbuilder_set_delta_search(pb, 0);
	cl_git_pass(git_packbuilder_insert(pb, &other, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &base, NULL));
	cl_git_pass(git_packbuilder_write(pb, "elsewhere.git/objects/pack", 0, NULL, NULL));
	git_str_puts(&path, "elsewhere.git/objects/pack/");
	get_packfile_path(&path, pb);
	times[0].tv_sec = times[1].tv_sec = time(NULL) + 3600;
	times[0].tv_usec = times[1].tv_usec = 0;
	cl_git_pass(p_utimes(path.ptr, times));
	git_str_dispose(&path);
	git_packbuilder_free(pb);

	cl_git_pass(git_repository_odb(&odb, repo));
	cl_git_pass(git_odb_refresh(odb));
	git_odb_free(odb);

	cl_git_pass(git_packbuilder_new(&pb, repo));
	git_packbuilder_set_delta_search(pb, 0);
	git_packbuilder_set_copy_compressed(pb, 1);
	cl_git_pass(git_packbuilder_insert(pb, &other, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &base, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &delta, NULL));
	cl_git_pass(git_packbuilder__prepare(pb));

	/* the delta is found in the older pack and its base whole in the newer */
	po = pb->object_list + 2;
	cl_assert_equal_oid(&delta, &po->id);
	cl_assert_equal_i(1, git_packbuilder__reused_count(pb));
	cl_assert(po->reuse_pack != NULL && po->delta != NULL);
	cl_assert(po->delta->whole_pack != NULL && po->delta->whole_pack != po->reuse_pack);

	write_and_verify(pb);
	cl_assert_equal_i(3, git_packbuilder__copied_count(pb));

	git_packbuilder_free(pb);
	git_repository_free(repo);
}

/* an indexer reading the pack written writes the same index, byte for byte */
static void assert_indexer_writes_same_index(git_packbuilder *pb)
{
	git_indexer *indexer;
	git_indexer_progress stats = { 0 };
	git_str pack = GIT_STR_INIT, idx = GIT_STR_INIT, other = GIT_STR_INIT;
	git_str contents = GIT_STR_INIT, ours = GIT_STR_INIT, theirs = GIT_STR_INIT;

	get_packfile_path(&pack, pb);
	get_index_path(&idx, pb);
	cl_git_pass(git_futils_readbuffer(&contents, pack.ptr));

	cl_git_pass(p_mkdir("reindexed", 0777));
#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_indexer_new(&indexer, "reindexed", NULL));
#else
	cl_git_pass(git_indexer_new(&indexer, "reindexed", 0, NULL, NULL));
#endif
	cl_git_pass(git_indexer_append(indexer, contents.ptr, contents.size, &stats));
	cl_git_pass(git_indexer_commit(indexer, &stats));
	cl_assert_equal_s(git_packbuilder_name(pb), git_indexer_name(indexer));

	git_str_puts(&other, "reindexed/");
	git_str_puts(&other, idx.ptr);
	cl_git_pass(git_futils_readbuffer(&ours, idx.ptr));
	cl_git_pass(git_futils_readbuffer(&theirs, other.ptr));
	cl_assert_equal_i(theirs.size, ours.size);
	cl_assert(memcmp(theirs.ptr, ours.ptr, ours.size) == 0);

	git_indexer_free(indexer);
	git_str_dispose(&pack);
	git_str_dispose(&idx);
	git_str_dispose(&other);
	git_str_dispose(&contents);
	git_str_dispose(&ours);
	git_str_dispose(&theirs);
}

void test_pack_packbuilder__writes_index_from_ids_when_copying(void)
{
	git_packbuilder_set_delta_search(_packbuilder, 0);
	git_packbuilder_set_copy_compressed(_packbuilder, 1);
	git_packbuilder_set_index_from_ids(_packbuilder, 1);
	seed_every_object();
	write_and_verify_pack();

	cl_assert_equal_i(_packbuilder->nr_objects, git_packbuilder__copied_count(_packbuilder));
	assert_indexer_writes_same_index(_packbuilder);
}

void test_pack_packbuilder__writes_index_from_ids_with_delta_search(void)
{
	git_packbuilder_set_reuse_delta(_packbuilder, 0);
	git_packbuilder_set_index_from_ids(_packbuilder, 1);
	seed_every_object();
	write_and_verify_pack();

	/* every object went through the search, so deltas it found are written too */
	cl_assert(_packbuilder->nr_deltified > 0);
	assert_indexer_writes_same_index(_packbuilder);
}

/* points id at the entry of other in a version 2 index, as damage to it could */
static void point_index_entry(const char *idx_path, const git_oid *id, const git_oid *other)
{
	git_str contents = GIT_STR_INIT;
	unsigned char *data, *ids, *offsets;
	uint32_t count, i, from = UINT32_MAX, to = UINT32_MAX;

	cl_git_pass(git_futils_readbuffer(&contents, idx_path));
	data = (unsigned char *)contents.ptr;
	count = ntohl(((uint32_t *)data)[2 + 255]);
	ids = data + 8 + 4 * 256;
	offsets = ids + (size_t)count * (GIT_OID_SHA1_SIZE + 4);

	for (i = 0; i < count; i++) {
		if (!memcmp(ids + i * GIT_OID_SHA1_SIZE, id->id, GIT_OID_SHA1_SIZE))
			from = i;
		if (!memcmp(ids + i * GIT_OID_SHA1_SIZE, other->id, GIT_OID_SHA1_SIZE))
			to = i;
	}
	cl_assert(from != UINT32_MAX && to != UINT32_MAX);
	memcpy(offsets + 4 * from, offsets + 4 * to, 4);

	cl_git_pass(p_chmod(idx_path, 0644));
	cl_git_pass(git_futils_writebuffer(&contents, idx_path, O_WRONLY | O_TRUNC, 0644));
	git_str_dispose(&contents);
}

static void remove_loose_object(const char *objects, const git_oid *id)
{
	git_str path = GIT_STR_INIT;
	char hex[GIT_OID_SHA1_HEXSIZE + 1];

	git_oid_tostr(hex, sizeof(hex), id);
	git_str_printf(&path, "%s/%.2s/%s", objects, hex, hex + 2);
	cl_git_pass(p_unlink(path.ptr));
	git_str_dispose(&path);
}

/*
 * Without an indexer reading every object back, an index pointing an id at the
 * entry of another object would have that object's delta written under the id,
 * as its sizes are read through the same index entry. The checksum the index
 * has for the id, which is of its own entry, stops it, whether the delta is
 * copied as it is or decompressed.
 */
void test_pack_packbuilder__index_from_ids_checks_reused_deltas_against_their_index(void)
{
	git_repository *repo;
	git_packbuilder *pb;
	git_odb *odb;
	git_str text = GIT_STR_INIT, idx = GIT_STR_INIT;
	git_oid first, second, other, delta;
	git_pobject *po = NULL;
	size_t i;
	int copy;

	cl_git_pass(git_repository_init(&repo, "damaged.git", 1));

	for (i = 0; i < 100; i++)
		git_str_printf(&text, "line %d of a file long enough to be worth a delta\n", (int)i);
	cl_git_pass(git_blob_create_from_buffer(&first, repo, text.ptr, text.size));
	git_str_puts(&text, "and one more line\n");
	cl_git_pass(git_blob_create_from_buffer(&second, repo, text.ptr, text.size));
	cl_git_pass(git_blob_create_from_buffer(&other, repo, "something else\n", 15));
	git_str_dispose(&text);

	cl_git_pass(git_packbuilder_new(&pb, repo));
	cl_git_pass(git_packbuilder_insert(pb, &first, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &second, NULL));
	cl_git_pass(git_packbuilder_insert(pb, &other, NULL));
	cl_git_pass(git_packbuilder_write(pb, "damaged.git/objects/pack", 0, NULL, NULL));
	for (i = 0; i < pb->nr_objects; i++) {
		if (pb->object_list[i].delta)
			po = pb->object_list + i;
	}
	cl_assert(po != NULL);
	git_oid_cpy(&delta, &po->id);
	git_str_puts(&idx, "damaged.git/objects/pack/");
	get_index_path(&idx, pb);
	git_packbuilder_free(pb);

	/* the objects are only in the pack, where the entry of other is the delta */
	remove_loose_object("damaged.git/objects", &first);
	remove_loose_object("damaged.git/objects", &second);
	remove_loose_object("damaged.git/objects", &other);
	point_index_entry(idx.ptr, &other, &delta);

	cl_git_pass(git_repository_odb(&odb, repo));
	cl_git_pass(git_odb_refresh(odb));
	git_odb_free(odb);

	for (copy = 0; copy <= 1; copy++) {
		cl_git_pass(git_packbuilder_new(&pb, repo));
		git_packbuilder_set_delta_search(pb, 0);
		git_packbuilder_set_copy_compressed(pb, copy);
		git_packbuilder_set_index_from_ids(pb, 1);
		cl_git_pass(git_packbuilder_insert(pb, &other, NULL));
		cl_git_pass(git_packbuilder_insert(pb, &first, NULL));
		cl_git_pass(git_packbuilder_insert(pb, &second, NULL));

		cl_git_fail(git_packbuilder_write(pb, "damaged.git/objects/pack", 0, NULL, NULL));
		cl_assert(strstr(git_error_last()->message, "checksum in its pack index") != NULL);
		git_packbuilder_free(pb);
	}

	git_str_dispose(&idx);
	git_repository_free(repo);
}

void test_pack_packbuilder__write_default_path(void)
{
	git_str idx = GIT_STR_INIT, pack = GIT_STR_INIT;

	seed_packbuilder();

	cl_git_pass(git_packbuilder_write(_packbuilder, NULL, 0, NULL, NULL));

	git_str_puts(&idx, "objects/pack/");
	get_index_path(&idx, _packbuilder);

	git_str_puts(&pack, "objects/pack/");
	get_packfile_path(&pack, _packbuilder);

	cl_assert(git_fs_path_exists(idx.ptr));
	cl_assert(git_fs_path_exists(pack.ptr));

	git_str_dispose(&idx);
	git_str_dispose(&pack);
}

static void test_write_pack_permission(mode_t given, mode_t expected)
{
	struct stat statbuf;
	mode_t mask, os_mask;
	git_str idx = GIT_STR_INIT, pack = GIT_STR_INIT;

	seed_packbuilder();

	cl_git_pass(git_packbuilder_write(_packbuilder, ".", given, NULL, NULL));

	/* Windows does not return group/user bits from stat,
	* files are never executable.
	*/
#ifdef GIT_WIN32
	os_mask = 0600;
#else
	os_mask = 0777;
#endif

	mask = p_umask(0);
	p_umask(mask);

	get_index_path(&idx, _packbuilder);
	get_packfile_path(&pack, _packbuilder);

	cl_git_pass(p_stat(idx.ptr, &statbuf));
	cl_assert_equal_i(statbuf.st_mode & os_mask, (expected & ~mask) & os_mask);

	cl_git_pass(p_stat(pack.ptr, &statbuf));
	cl_assert_equal_i(statbuf.st_mode & os_mask, (expected & ~mask) & os_mask);

	git_str_dispose(&idx);
	git_str_dispose(&pack);
}

void test_pack_packbuilder__permissions_standard(void)
{
	test_write_pack_permission(0, GIT_PACK_FILE_MODE);
}

void test_pack_packbuilder__permissions_readonly(void)
{
	test_write_pack_permission(0444, 0444);
}

void test_pack_packbuilder__permissions_readwrite(void)
{
	test_write_pack_permission(0666, 0666);
}

void test_pack_packbuilder__does_not_fsync_by_default(void)
{
	seed_packbuilder();
	cl_git_pass(git_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(0, p_fsync__cnt);
}

/* We fsync the packfile and index.  On non-Windows, we also fsync
 * the parent directories.
 */
#ifdef GIT_WIN32
static int expected_fsyncs = 2;
#else
static int expected_fsyncs = 4;
#endif

void test_pack_packbuilder__fsync_global_setting(void)
{
	cl_git_pass(git_libgit2_opts(GIT_OPT_ENABLE_FSYNC_GITDIR, 1));
	p_fsync__cnt = 0;
	seed_packbuilder();
	cl_git_pass(git_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(expected_fsyncs, p_fsync__cnt);
}

void test_pack_packbuilder__fsync_repo_setting(void)
{
	cl_repo_set_bool(_repo, "core.fsyncObjectFiles", true);
	p_fsync__cnt = 0;
	seed_packbuilder();
	cl_git_pass(git_packbuilder_write(_packbuilder, ".", 0666, NULL, NULL));
	cl_assert_equal_sz(expected_fsyncs, p_fsync__cnt);
}

static int foreach_cb(void *buf, size_t len, void *payload)
{
	git_indexer *idx = (git_indexer *) payload;
	cl_git_pass(git_indexer_append(idx, buf, len, &_stats));
	return 0;
}

void test_pack_packbuilder__foreach(void)
{
	git_indexer *idx;

	seed_packbuilder();

#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_indexer_new(&idx, ".", NULL));
#else
	cl_git_pass(git_indexer_new(&idx, ".", 0, NULL, NULL));
#endif

	cl_git_pass(git_packbuilder_foreach(_packbuilder, foreach_cb, idx));
	cl_git_pass(git_indexer_commit(idx, &_stats));
	git_indexer_free(idx);
}

static int foreach_cancel_cb(void *buf, size_t len, void *payload)
{
	git_indexer *idx = (git_indexer *)payload;
	cl_git_pass(git_indexer_append(idx, buf, len, &_stats));
	return (_stats.total_objects > 2) ? -1111 : 0;
}

void test_pack_packbuilder__foreach_with_cancel(void)
{
	git_indexer *idx;

	seed_packbuilder();

#ifdef GIT_EXPERIMENTAL_SHA256
	cl_git_pass(git_indexer_new(&idx, ".", NULL));
#else
	cl_git_pass(git_indexer_new(&idx, ".", 0, NULL, NULL));
#endif

	cl_git_fail_with(
		git_packbuilder_foreach(_packbuilder, foreach_cancel_cb, idx), -1111);
	git_indexer_free(idx);
}

void test_pack_packbuilder__keep_file_check(void)
{
	assert(!git_disable_pack_keep_file_checks);
	cl_git_pass(git_libgit2_opts(GIT_OPT_DISABLE_PACK_KEEP_FILE_CHECKS, true));
	assert(git_disable_pack_keep_file_checks);
}
