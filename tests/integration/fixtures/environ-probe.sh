# Counts the other processes whose /proc/<pid>/environ holds an assignment
# matching $1 (a grep pattern); prints `environ-seen=<n>`. Shared by
# test_pi_srt.sh and test_toolchains.sh.
n=0
for p in /proc/[0-9]*; do
  [ "${p#/proc/}" = "$$" ] && continue
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q -- "$1" && n=$((n+1))
done
echo "environ-seen=$n"
