#define DIFF_RENAME_CIRCULAR \
	"diff --git a/asparagus.txt b/beef.txt\n" \
	"similarity index 100%\n" \
	"rename from asparagus.txt\n" \
	"rename to beef.txt\n" \
	"diff --git a/beef.txt b/notbeef.txt\n" \
	"similarity index 100%\n" \
	"rename from beef.txt\n" \
	"rename to asparagus.txt\n"

#define DIFF_RENAME_2_TO_1 \
	"diff --git a/asparagus.txt b/2.txt\n" \
	"similarity index 100%\n" \
	"rename from asparagus.txt\n" \
	"rename to 2.txt\n" \
	"diff --git a/beef.txt b/2.txt\n" \
	"similarity index 100%\n" \
	"rename from beef.txt\n" \
	"rename to 2.txt\n"

#define DIFF_RENAME_1_TO_2 \
	"diff --git a/asparagus.txt b/2.txt\n" \
	"similarity index 100%\n" \
	"rename from asparagus.txt\n" \
	"rename to 1.txt\n" \
	"diff --git a/asparagus.txt b/2.txt\n" \
	"similarity index 100%\n" \
	"rename from asparagus.txt\n" \
	"rename to 2.txt\n"

#define DIFF_TWO_DELTAS_ONE_FILE \
	"diff --git a/beef.txt b/beef.txt\n" \
	"index 68f6182..235069d 100644\n" \
	"--- a/beef.txt\n" \
	"+++ b/beef.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-BEEF SOUP.\n" \
	"+BEEF SOUP!\n" \
	"\n" \
	" Take the hind shin of beef, cut off all the flesh off the leg-bone,\n" \
	" which must be taken away entirely, or the soup will be greasy. Wash the\n" \
	"diff --git a/beef.txt b/beef.txt\n" \
	"index 68f6182..e059eb5 100644\n" \
	"--- a/beef.txt\n" \
	"+++ b/beef.txt\n" \
	"@@ -19,4 +19,4 @@ a ladle full of the soup, a little at a time; stirring it all the while.\n" \
	" Strain this browning and mix it well with the soup; take out the bundle\n" \
	" of thyme and parsley, put the nicest pieces of meat in your tureen, and\n" \
	" pour on the soup and vegetables; put in some toasted bread cut in dice,\n" \
	"-and serve it up.\n" \
	"+and serve it up!\n"

#define DIFF_TWO_DELTAS_ONE_NEW_FILE \
	"diff --git a/newfile.txt b/newfile.txt\n" \
	"new file mode 100644\n" \
	"index 0000000..6434b13\n" \
	"--- /dev/null\n" \
	"+++ b/newfile.txt\n" \
	"@@ -0,0 +1 @@\n" \
	"+This is a new file.\n" \
	"diff --git a/newfile.txt b/newfile.txt\n" \
	"index 6434b13..08d4c44 100644\n" \
	"--- a/newfile.txt\n" \
	"+++ b/newfile.txt\n" \
	"@@ -1 +1,3 @@\n" \
	" This is a new file.\n" \
	"+\n" \
	"+This is another change to a new file.\n"

#define DIFF_RENAME_AND_MODIFY_DELTAS \
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
	"diff --git a/asdf.txt b/asdf.txt\n" \
	"index 292cb60..61c686b 100644\n" \
	"--- a/asdf.txt\n" \
	"+++ b/asdf.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP\n" \
	"\n" \
	" Put into a pot three quarts of water, three onions cut small, one\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n"
