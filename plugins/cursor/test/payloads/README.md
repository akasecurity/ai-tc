# Cursor hook payloads

Constructed from Cursor's published hooks reference, not recorded from a live
Cursor session. Each file is one stdin payload for the event it is named after.
The ids, paths and model are placeholders; the tests re-point `cwd` and
`workspace_roots` at a temporary checkout and replace the text being scanned.

Recording these from a real Cursor install, and replacing them with what was
seen, is the step that would turn this plugin's capability rows from
doc-derived into verified.

To record them, turn on the plugin's hook recordings (see the plugin README):
each file's `stdin` value is the payload to save here.
