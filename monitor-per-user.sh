own=$(id -nu)
cpus=$(lscpu | grep "^CPU(s):" | awk '{print $2}')

# System total CPU usage
# Avoided using top command because it may brings much overhead to a rather idle machine
# top -b -n 1 | awk -F'[,[:blank:]]+' 'NR == 3 { print "system " 100-$8 }'
awk '{u=$2+$4; t=$2+$4+$5; if (NR==1) {u1=u; t1=t;} else print "system " ($2+$4-u1) * 100 / (t-t1); }' \
    <(grep 'cpu ' /proc/stat) <(sleep 1;grep 'cpu ' /proc/stat)

for user in $(ps au | awk 'NR>1 {print $1}' | sort -u)
do
    # print other user's CPU usage in parallel but skip own one because
    # spawning many processes will increase our CPU usage significantly
    if [ "$user" = "$own" ]; then continue; fi
    (top -b -n 1 -u "$user" | awk -v user=$user -v CPUS=$cpus 'NR>7 { sum += $9; } END { print user, sum, sum/CPUS; }') &
    # don't spawn too many processes in parallel
    sleep 0.05
done
wait

# print own CPU usage after all spawned processes completed
# top -b -n 1 -u "$own" | awk -v user=$own -v CPUS=$cpus 'NR>7 { sum += $9; } END { print user, sum, sum/CPUS; }'