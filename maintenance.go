package main

// TODO: in our maintenance loop, we will want to check files in our badfiles hashlist.
// for the matches: we want to
// 1. purge the file (all files by that owner, e.g. call PurgeByFile from admin.go )
// 2. get the file owner's last address, if any
// 3. add that user's last ip range to the blacklist
