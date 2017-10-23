package version

// AnaxDistVersion identifies this runtime's distribution version.
// As of Oct. 2017 this is updated by horizon-pkg-deb when a package is built.
// It is updated to the version of the deb at build time. Other uses of Anax
// outside of the horizon-pkg-deb can manipulate this version for their own
// reporting purposes.
//
// The default value for this in development is purposefully high so that
// it doesn't need to be edited in development to test new features in
// collaborators that check for new versions. This version is intended to never
// match a real, released version.
const AnaxDistVersion = "9.9.99~~rc99"
