# Nexus

Front end for Nexus. Static site, no build step. The server is in the `Nexus` repo (`main.ts`).

```
index.html        page markup (auth screen, app shell, modals, admin panel)
css/              stylesheets, loaded in this order (later files override earlier ones)
  base.css          variables, auth screen, profile page, hover popups
  layout.css        rail, sidebar, chat, members, DMs, modals, toasts
  polish.css        visual refinements
  animations.css    animations, audio player, home screen
  makeover.css      final sizing and spacing pass
js/               scripts, loaded in this order (they share one global scope)
  state.js          server address, app state, emoji data
  auth.js           login, signup, password change
  app.js            bootApp, announcements
  websocket.js      connection, reconnect, send queue
  ws-handler.js     handleIn: handles every message from the server
  ...               one file per feature (servers, channels, messages, DMs,
                    friends, voice, admin, shorts, and so on)
  main.js           starts the app
  update-check.js   "new version available" banner
```

Scripts are plain `<script>` tags, not modules, so the order in `index.html` matters.
The `onclick="..."` handlers in the markup call functions defined in these files.
