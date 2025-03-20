#!/bin/bash

# Add secrets to .gitignore if not already present
if ! grep -q ".env" .gitignore; then
  echo ".env" >> .gitignore
  echo ".env.*" >> .gitignore
  echo "firebase-service-account.json" >> .gitignore
  echo "Added .env and firebase-service-account.json to .gitignore"
else
  echo ".env and firebase-service-account.json already in .gitignore"
fi

# Untrack the secrets if already added to git
git rm --cached -f .env 2>/dev/null
git rm --cached -f firebase-service-account.json 2>/dev/null

# Add .gitignore changes and commit
git add .gitignore
git commit -m "Add .env and firebase-service-account.json to .gitignore and remove from tracking" || echo "Nothing to commit."

# Push changes
git push origin main
