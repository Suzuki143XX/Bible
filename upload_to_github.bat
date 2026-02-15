@echo off
echo ============================================
echo Upload Bible AI to GitHub
echo ============================================
echo.

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed!
    echo Please download from: https://git-scm.com/download/win
    echo Or use GitHub Desktop instead: https://desktop.github.com/
    pause
    exit /b 1
)

echo Git is installed! ✓
echo.

REM Get GitHub username
set /p USERNAME=Enter your GitHub username: 

REM Get repo name (default: bible-ai)
set /p REPONAME=Enter repository name (press Enter for 'bible-ai'): 
if "%REPONAME%"=="" set REPONAME=bible-ai

echo.
echo ============================================
echo Creating repository: %REPONAME%
echo ============================================
echo.

REM Initialize git if not already done
if not exist ".git" (
    git init
    echo Git repository initialized
) else (
    echo Git already initialized
)

REM Add all files
echo.
echo Adding files...
git add .

REM Commit
echo.
echo Committing files...
git commit -m "Initial commit" 2>nul || echo Already committed

REM Set branch name
git branch -M main

REM Add remote
echo.
echo Setting up GitHub remote...
git remote remove origin 2>nul
git remote add origin https://github.com/%USERNAME%/%REPONAME%.git

echo.
echo ============================================
echo Ready to push to GitHub!
echo ============================================
echo.
echo Make sure you:
echo 1. Created the repository on GitHub first
echo 2. Go to https://github.com/new and create "%REPONAME%"
echo.

pause

echo.
echo Pushing to GitHub...
git push -u origin main

if errorlevel 1 (
    echo.
    echo ERROR: Push failed!
    echo Common issues:
    echo - Repository doesn't exist on GitHub yet
    echo - Wrong username or repo name
    echo - Not logged in to Git
    echo.
    echo Go to https://github.com/new and create the repository first!
) else (
    echo.
    echo ============================================
    echo SUCCESS! Uploaded to GitHub!
    echo ============================================
    echo.
    echo View your repo: https://github.com/%USERNAME%/%REPONAME%
)

pause
