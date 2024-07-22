Removes Windows bloat (appx packages) from user profiles and machine-wide. Profiles with active sessions will be skipped. 
User-based app removal finishes for a user when they log in next. See list of apps to be removed under release notes.

If you want to edit the list you will need to use the script instead of the exe. The'DisplayName' value is what is used to 
identify the app for removal. Run **get-AppxProvisionedPackage -online** to get the displayname for an app.

