for i in {1..150}; do
    dynostore --server localhost:80 get 9766eadd-3eac-4bd4-b72c-09e09daab733 --output testdown.dat
done