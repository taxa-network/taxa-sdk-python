for i in {1..15}; do
    python -mtaxa_sdk.tests --forcenode=Dev${i} SnippetTest > /dev/null 2>&1;
    if [ $? -eq 0 ]
    then
        echo "Dev$i: pass"
    else
        echo "Dev$i: fail"
    fi
done
