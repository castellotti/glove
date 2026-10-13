{% for name, p in settings.plugins.items() %}
- Plugin **{{ name }}** is installed read-only at `/opt/glove/plugins/{{ name }}`{% if p.skills is defined %} (skills: {{ p.skills | join(", ") }}){% endif %}; its writable data directory is `/work/.glove-plugin-data/{{ name }}`.
{%- endfor %}
{% if settings.plugins %}
- Plugin scripts run in your sandbox like any shell command: no network, and Python scripts (`uv run --script`) only with the packages baked in. When a script can't reach the service it needs, tell the operator; never work around it, and never try to obtain or store a credential yourself.
{% endif %}
