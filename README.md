# Nexus

Front end for Nexus. Static site, no build step. The server is in the `Nexus` repo (`main.ts`).

```
index.html        page markup (auth screen, app shell, modals, admin panel)
css/              stylesheets, loaded in this order
  tokens.css        design tokens (Discord dark palette), reset, scrollbars, tooltip
  shell.css         rail, sidebar, user panel, header, members, DM panel, home, discover
  chat.css          messages, composer, reactions, attachments, pickers, shorts
  components.css    buttons, forms, modals, auth, profile cards, toasts, settings
  motion.css        in/out animation for anything JS shows/hides with inline display
js/               scripts, loaded in this order (they share one global scope)
  state.js          server address, app state, emoji data
  auth.js           login, signup, password change
  app.js            bootApp, announcements
  websocket.js      connection, reconnect, send queue
  ws-handler.js     handleIn: handles every message from the server
  ...               one file per feature (servers, channels, messages, DMs,
                    friends, voice, admin, shorts, and so on)
  tooltips.js       floating tooltip for icon buttons
  main.js           starts the app
  update-check.js   "new version available" banner
```

Scripts are plain `<script>` tags, not modules, so the order in `index.html` matters.
They sit at the end of `<body>` so every element they touch at boot already exists.
The `onclick="..."` handlers in the markup call functions defined in these files.
