#define DIFF_MANY_CHANGES_ONE \
	"diff --git a/veal.txt b/veal.txt\n" \
	"index 94d2c01..c9d7d5d 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/veal.txt\n" \
	"@@ -1,2 +1,2 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP\n" \
	" \n" \
	"@@ -4,3 +4,2 @@\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n" \
	"-slices of lean ham; let it boil steadily two hours; skim it\n" \
	" occasionally, then put into it a shin of veal, let it boil two hours\n" \
	"@@ -8,3 +7,3 @@\n" \
	" should rise, take a gill of good cream, mix with it two table-spoonsful\n" \
	"-of flour very nicely, and the yelks of two eggs beaten well, strain this\n" \
	"+OF FLOUR very nicely, and the yelks of two eggs beaten well, strain this\n" \
	" mixture, and add some chopped parsley; pour some soup on by degrees,\n" \
	"@@ -12,2 +11,3 @@\n" \
	" boiled two or three minutes to take off the raw taste of the eggs. If\n" \
	"+Inserted line.\n" \
	" the cream be not perfectly sweet, and the eggs quite new, the thickening\n" \
	"@@ -15,3 +15,3 @@\n" \
	" in, first taking off their skins, by letting them stand a few minutes in\n" \
	"-hot water, when they may be easily peeled. When made in this way you\n" \
	"+Changed line.\n" \
	" must thicken it with the flour only. Any part of the veal may be used,\n"

#define DIFF_MANY_CHANGES_TWO \
	"diff --git a/veal.txt b/veal.txt\n" \
	"index 94d2c01..6b943d6 100644\n" \
	"--- a/veal.txt\n" \
	"+++ b/veal.txt\n" \
	"@@ -1,2 +1,2 @@\n" \
	"-VEAL SOUP!\n" \
	"+VEAL SOUP!!!\n" \
	" \n" \
	"@@ -4,3 +4,2 @@\n" \
	" spoonful of black pepper pounded, and two of salt, with two or three\n" \
	"-slices of lean ham; let it boil steadily two hours; skim it\n" \
	" occasionally, then put into it a shin of veal, let it boil two hours\n" \
	"@@ -8,3 +7,3 @@\n" \
	" should rise, take a gill of good cream, mix with it two table-spoonsful\n" \
	"-of flour very nicely, and the yelks of two eggs beaten well, strain this\n" \
	"+of flour very nicely, AND the yelks of two eggs beaten well, strain this\n" \
	" mixture, and add some chopped parsley; pour some soup on by degrees,\n" \
	"@@ -12,2 +11,3 @@\n" \
	" boiled two or three minutes to take off the raw taste of the eggs. If\n" \
	"+New line.\n" \
	" the cream be not perfectly sweet, and the eggs quite new, the thickening\n" \
	"@@ -15,4 +15,5 @@\n" \
	" in, first taking off their skins, by letting them stand a few minutes in\n" \
	"-hot water, when they may be easily peeled. When made in this way you\n" \
	"-must thicken it with the flour only. Any part of the veal may be used,\n" \
	"-but the shin or knuckle is the nicest.\n" \
	"+HOT water, when they may be easily peeled. When made in this way you\n" \
	"+must THICKEN it with the flour only. Any part of the veal may be used,\n" \
	"+but the shin OR knuckle is the nicest.\n" \
	"+Another new line.\n" \

#define DIFF_RENAME_FILE \
	"diff --git a/beef.txt b/notbeef.txt\n" \
	"similarity index 100%\n" \
	"rename from beef.txt\n" \
	"rename to notbeef.txt\n"

#define DIFF_RENAME_AND_MODIFY_FILE \
	"diff --git a/beef.txt b/notbeef.txt\n" \
	"similarity index 97%\n" \
	"rename from beef.txt\n" \
	"rename to notbeef.txt\n" \
	"index 68f6182..6fa1014 100644\n" \
	"--- a/beef.txt\n" \
	"+++ b/notbeef.txt\n" \
	"@@ -1,4 +1,4 @@\n" \
	"-BEEF SOUP.\n" \
	"+THIS IS NOT BEEF SOUP, IT HAS A NEW NAME.\n" \
	"\n" \
	" Take the hind shin of beef, cut off all the flesh off the leg-bone,\n" \
	" which must be taken away entirely, or the soup will be greasy. Wash the\n"

#define DIFF_RENAME_A_TO_B_TO_C \
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
	"diff --git a/beef.txt b/beef.txt\n" \
	"index 68f6182..f516580 100644\n" \
	"--- a/beef.txt\n" \
	"+++ b/beef.txt\n" \
	"@@ -1,22 +1,10 @@\n" \
	"-BEEF SOUP.\n" \
	"+ASPARAGUS SOUP!\n" \
	"\n" \
	"-Take the hind shin of beef, cut off all the flesh off the leg-bone,\n" \
	"-which must be taken away entirely, or the soup will be greasy. Wash the\n" \
	"-meat clean and lay it in a pot, sprinkle over it one small\n" \
	"-table-spoonful of pounded black pepper, and two of salt; three onions\n" \
	"-the size of a hen's egg, cut small, six small carrots scraped and cut\n" \
	"-up, two small turnips pared and cut into dice; pour on three quarts of\n" \
	"-water, cover the pot close, and keep it gently and steadily boiling five\n" \
	"-hours, which will leave about three pints of clear soup; do not let the\n" \
	"-pot boil over, but take off the scum carefully, as it rises. When it has\n" \
	"-boiled four hours, put in a small bundle of thyme and parsley, and a\n" \
	"-pint of celery cut small, or a tea-spoonful of celery seed pounded.\n" \
	"-These latter ingredients would lose their delicate flavour if boiled too\n" \
	"-much. Just before you take it up, brown it in the following manner: put\n" \
	"-a small table-spoonful of nice brown sugar into an iron skillet, set it\n" \
	"-on the fire and stir it till it melts and looks very dark, pour into it\n" \
	"-a ladle full of the soup, a little at a time; stirring it all the while.\n" \
	"-Strain this browning and mix it well with the soup; take out the bundle\n" \
	"-of thyme and parsley, put the nicest pieces of meat in your tureen, and\n" \
	"-pour on the soup and vegetables; put in some toasted bread cut in dice,\n" \
	"-and serve it up.\n" \
	"+Take four large bunches of asparagus, scrape it nicely, cut off one inch\n" \
	"+of the tops, and lay them in water, chop the stalks and put them on the\n" \
	"+fire with a piece of bacon, a large onion cut up, and pepper and salt;\n" \
	"+add two quarts of water, boil them till the stalks are quite soft, then\n" \
	"+pulp them through a sieve, and strain the water to it, which must be put\n" \
	"+back in the pot; put into it a chicken cut up, with the tops of\n" \
	"+asparagus which had been laid by, boil it until these last articles are\n" \
	"+sufficiently done, thicken with flour, butter and milk, and serve it up.\n" \
	"diff --git a/notbeef.txt b/notbeef.txt\n" \
	"new file mode 100644\n" \
	"index 0000000..68f6182\n" \
	"--- /dev/null\n" \
	"+++ b/notbeef.txt\n" \
	"@@ -0,0 +1,22 @@\n" \
	"+BEEF SOUP.\n" \
	"+\n" \
	"+Take the hind shin of beef, cut off all the flesh off the leg-bone,\n" \
	"+which must be taken away entirely, or the soup will be greasy. Wash the\n" \
	"+meat clean and lay it in a pot, sprinkle over it one small\n" \
	"+table-spoonful of pounded black pepper, and two of salt; three onions\n" \
	"+the size of a hen's egg, cut small, six small carrots scraped and cut\n" \
	"+up, two small turnips pared and cut into dice; pour on three quarts of\n" \
	"+water, cover the pot close, and keep it gently and steadily boiling five\n" \
	"+hours, which will leave about three pints of clear soup; do not let the\n" \
	"+pot boil over, but take off the scum carefully, as it rises. When it has\n" \
	"+boiled four hours, put in a small bundle of thyme and parsley, and a\n" \
	"+pint of celery cut small, or a tea-spoonful of celery seed pounded.\n" \
	"+These latter ingredients would lose their delicate flavour if boiled too\n" \
	"+much. Just before you take it up, brown it in the following manner: put\n" \
	"+a small table-spoonful of nice brown sugar into an iron skillet, set it\n" \
	"+on the fire and stir it till it melts and looks very dark, pour into it\n" \
	"+a ladle full of the soup, a little at a time; stirring it all the while.\n" \
	"+Strain this browning and mix it well with the soup; take out the bundle\n" \
	"+of thyme and parsley, put the nicest pieces of meat in your tureen, and\n" \
	"+pour on the soup and vegetables; put in some toasted bread cut in dice,\n" \
	"+and serve it up.\n"

#define DIFF_RENAME_A_TO_B_TO_C_EXACT \
	"diff --git a/asparagus.txt b/beef.txt\n" \
	"similarity index 100%\n" \
	"rename from asparagus.txt\n" \
	"rename to beef.txt\n" \
	"diff --git a/beef.txt b/notbeef.txt\n" \
	"similarity index 100%\n" \
	"rename from beef.txt\n" \
	"rename to notbeef.txt\n"
