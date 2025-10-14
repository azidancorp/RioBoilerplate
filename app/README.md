# app

This is a placeholder README for your project. Use it to describe what your
project is about, to give new users a quick overview of what they can expect.

_App_ was created using [Rio](https://rio.dev/), an easy to
use app & website framework for Python._

This project is based on the `Authentication` template.

## Authentication

## Authentication

This template demonstrates how to implement user authentication in your app. It
uses SQLite to store user data, but you are of course free to replace it with
whichever persistence mechanism you prefer.

## Outline

All database access is done using a `Persistence` class. This abstracts away the
database operations and makes it easy to switch to a different database if
needed. This class is attached to the session to make it easily retrievable
throughout the app.

When a user logs in, two things happen:

- A session token is stored on the user's device so the user can be recognized
  on subsequent visits.
- Information about the user, such as their ID and email address are attached to the
  session. This indicates to the app that somebody is logged in, and who that
  person is.

Any pages that shouldn't be accessible without logging in are protected using
Rio's guard mechanism.

By default, email addresses are the primary user identifiers. If you ever need
username-based logins for a particular deployment, set the environment variable
`RIO_ALLOW_USERNAME_LOGIN=true` before starting the app to enable a username
fallback while keeping email as the recommended path.
