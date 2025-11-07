####################################
###### Developed By Ryan Deyo ######
####################################

currentID="$1"
currentSSHID=$((currentID - 1))
echo "Current ID:" ${currentID}
echo "Current SSH ID: " ${currentSSHID}

pids=($(ps aux | grep ssh | awk '{print $2}'))
for pid in "${pids[@]}"; do
        if [ $pid == $currentSSHID ]; then
          echo ""
        else
                echo "Bad PID: $pid"
                kill -9 $pid
        fi
        sleep .5
done
