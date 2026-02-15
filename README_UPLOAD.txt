HOW TO UPLOAD TO GITHUB
========================

The folder drag-and-drop on GitHub doesn't work well.
Use one of these methods instead:

OPTION 1: GitHub Desktop (Easiest)
------------------------------------
1. Download: https://desktop.github.com/
2. Install and sign in
3. File -> Add local repository
4. Select this folder
5. Type "Initial commit" and click Commit
6. Click Publish repository
7. Name it "bible-ai"
8. Done!

OPTION 2: upload_to_github.bat
------------------------------
1. Make sure you have Git installed
   Download: https://git-scm.com/download/win
2. Double-click "upload_to_github.bat"
3. Enter your GitHub username
4. Enter repository name (or press Enter for "bible-ai")
5. Make sure you created the repo on GitHub first!
6. The script will upload everything

OPTION 3: Command Line
----------------------
1. Open Command Prompt in this folder
2. Run these commands:

   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/bible-ai.git
   git push -u origin main

========================
WHAT'S IN THIS FOLDER
========================

6 Files:
  - app.py (main application)
  - admin.py (admin panel)
  - requirements.txt (dependencies)
  - render.yaml (Render config)
  - .gitignore (ignore rules)
  - README.md (documentation)

2 Folders:
  - templates/ (9 HTML files)
  - static/ (1 JSON file)

Total: 17 files ready for upload
