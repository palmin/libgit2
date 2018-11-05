#define DIFF_RENAME_AFTER_MODIFY \
	"diff --git a/veal.txt b/veal.txt\n" \
	"index 292cb60..61c686b 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/veal.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP\n" \
	"\n" \
	" Put into a pot three quarts of water, three onions cut small, one\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n" \
	"diff --git a/veal.txt b/other.txt\n" \
	"similarity index 96%\n" \
	"rename from veal.txt\n" \
	"rename to other.txt\n" \
	"index 94d2c01..292cb60 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/other.txt\n" \
	"@@ -15,4 +15,4 @@ will curdle in the soup. For a change you may put a dozen ripe tomatos\n" \
	" in, first taking off their skins, by letting them stand a few minutes in\n" \
	" hot water, when they may be easily peeled. When made in this way you\n" \
	" must thicken it with the flour only. Any part of the veal may be used,\n" \
	"-but the shin or knuckle is the nicest.\n" \
	"+but the shin or knuckle is the nicest!\n"

#define DIFF_RENAME_AFTER_MODIFY_TARGET_PATH \
	"diff --git a/beef.txt b/beef.txt\n" \
	"index 292cb60..61c686b 100644\n" \
	"--- a/beef.txt\n" \
	"+++ b/beef.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP\n" \
	"\n" \
	" Put into a pot three quarts of water, three onions cut small, one\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n" \
	"diff --git a/veal.txt b/beef.txt\n" \
	"similarity index 96%\n" \
	"rename from veal.txt\n" \
	"rename to beef.txt\n" \
	"index 94d2c01..292cb60 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/beef.txt\n" \
	"@@ -15,4 +15,4 @@ will curdle in the soup. For a change you may put a dozen ripe tomatos\n" \
	" in, first taking off their skins, by letting them stand a few minutes in\n" \
	" hot water, when they may be easily peeled. When made in this way you\n" \
	" must thicken it with the flour only. Any part of the veal may be used,\n" \
	"-but the shin or knuckle is the nicest.\n" \
	"+but the shin or knuckle is the nicest!\n"

#define DIFF_RENAME_AND_MODIFY_SOURCE_PATH \
	"diff --git a/veal.txt b/asdf.txt\n" \
	"similarity index 96%\n" \
	"rename from veal.txt\n" \
	"rename to asdf.txt\n" \
	"index 94d2c01..292cb60 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/asdf.txt\n" \
	"@@ -15,4 +15,4 @@ will curdle in the soup. For a change you may put a dozen ripe tomatos\n" \
	" in, first taking off their skins, by letting them stand a few minutes in\n" \
	" hot water, when they may be easily peeled. When made in this way you\n" \
	" must thicken it with the flour only. Any part of the veal may be used,\n" \
	"-but the shin or knuckle is the nicest.\n" \
	"+but the shin or knuckle is the nicest!\n" \
	"diff --git a/veal.txt b/veal.txt\n" \
	"index 292cb60..61c686b 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/veal.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP\n" \
	"\n" \
	" Put into a pot three quarts of water, three onions cut small, one\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n"

#define DIFF_DELETE_AND_READD_FILE \
	"diff --git a/asparagus.txt b/asparagus.txt\n" \
	"deleted file mode 100644\n" \
	"index f516580..0000000\n" \
	"--- a/asparagus.txt\n" \
	"+++ /dev/null\n" \
	"@@ -1,10 +0,0 @@\n" \
	"-ASPARAGUS SOUP!\n" \
	"-\n" \
	"-Take four large bunches of asparagus, scrape it nicely, cut off one inch\n" \
	"-of the tops, and lay them in water, chop the stalks and put them on the\n" \
	"-fire with a piece of bacon, a large onion cut up, and pepper and salt;\n" \
	"-add two quarts of water, boil them till the stalks are quite soft, then\n" \
	"-pulp them through a sieve, and strain the water to it, which must be put\n" \
	"-back in the pot; put into it a chicken cut up, with the tops of\n" \
	"-asparagus which had been laid by, boil it until these last articles are\n" \
	"-sufficiently done, thicken with flour, butter and milk, and serve it up.\n" \
	"diff --git a/asparagus.txt b/asparagus.txt\n" \
	"new file mode 100644\n" \
	"index 0000000..2dc7f8b\n" \
	"--- /dev/null\n" \
	"+++ b/asparagus.txt\n" \
	"@@ -0,0 +1 @@\n" \
	"+New file.\n" \

#define DIFF_REMOVE_FILE_TWICE \
	"diff --git a/asparagus.txt b/asparagus.txt\n" \
	"deleted file mode 100644\n" \
	"index f516580..0000000\n" \
	"--- a/asparagus.txt\n" \
	"+++ /dev/null\n" \
	"@@ -1,10 +0,0 @@\n" \
	"-ASPARAGUS SOUP!\n" \
	"-\n" \
	"-Take four large bunches of asparagus, scrape it nicely, cut off one inch\n" \
	"-of the tops, and lay them in water, chop the stalks and put them on the\n" \
	"-fire with a piece of bacon, a large onion cut up, and pepper and salt;\n" \
	"-add two quarts of water, boil them till the stalks are quite soft, then\n" \
	"-pulp them through a sieve, and strain the water to it, which must be put\n" \
	"-back in the pot; put into it a chicken cut up, with the tops of\n" \
	"-asparagus which had been laid by, boil it until these last articles are\n" \
	"-sufficiently done, thicken with flour, butter and milk, and serve it up.\n" \
	"diff --git a/asparagus.txt b/asparagus.txt\n" \
	"deleted file mode 100644\n" \
	"index f516580..0000000\n" \
	"--- a/asparagus.txt\n" \
	"+++ /dev/null\n" \
	"@@ -1,10 +0,0 @@\n" \
	"-ASPARAGUS SOUP!\n" \
	"-\n" \
	"-Take four large bunches of asparagus, scrape it nicely, cut off one inch\n" \
	"-of the tops, and lay them in water, chop the stalks and put them on the\n" \
	"-fire with a piece of bacon, a large onion cut up, and pepper and salt;\n" \
	"-add two quarts of water, boil them till the stalks are quite soft, then\n" \
	"-pulp them through a sieve, and strain the water to it, which must be put\n" \
	"-back in the pot; put into it a chicken cut up, with the tops of\n" \
	"-asparagus which had been laid by, boil it until these last articles are\n" \
	"-sufficiently done, thicken with flour, butter and milk, and serve it up.\n"
