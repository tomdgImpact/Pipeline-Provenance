# Browser suite

Playwright coverage of the HTML audit report: it renders with no network
access, the findings are navigable, the displayed score matches the JSON
result for the same run, and the finding list is reachable by keyboard.

Lands with the renderer it covers (T015/T016). Until then this directory is
empty and the browser gate is absent from CI, rather than present and running
an empty selection.
