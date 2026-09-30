## Network: corporate resources only

This session reaches **only** the corporate resources its operator allowed, over
the host's corporate VPN; the general internet is refused (`web_fetch` gets a
403 from the proxy). Allowed: {% for h in slot.egress.guard_hosts %}`{{ h }}`{% if not loop.last %}, {% endif %}{% endfor %}{% if slot.egress.guard_hosts and slot.egress.guard_cidrs %}, {% endif %}{% for c in slot.egress.guard_cidrs %}`{{ c }}`{% if not loop.last %}, {% endif %}{% endfor %}.
{% if slot.egress.tcp %}
Raw TCP endpoints (connect to the forwarder, which dials the corporate host):
{% for t in slot.egress.tcp %}
- `{{ endpoint[t.name].host }}:{{ t.port }}` → `{{ t.to }}`
{% endfor %}
{% endif %}
If something you need is refused, say so and ask the operator to add it to the
session's `corporate:` allowlist — do not look for another way out.
