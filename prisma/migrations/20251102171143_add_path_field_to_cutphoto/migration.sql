/*
  Warnings:

  - You are about to drop the column `data` on the `CutPhoto` table. All the data in the column will be lost.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_CutPhoto" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "cutId" TEXT NOT NULL,
    "path" TEXT,
    "mimeType" TEXT,
    "position" INTEGER,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "CutPhoto_cutId_fkey" FOREIGN KEY ("cutId") REFERENCES "Cut" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_CutPhoto" ("createdAt", "cutId", "id", "mimeType", "position") SELECT "createdAt", "cutId", "id", "mimeType", "position" FROM "CutPhoto";
DROP TABLE "CutPhoto";
ALTER TABLE "new_CutPhoto" RENAME TO "CutPhoto";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
