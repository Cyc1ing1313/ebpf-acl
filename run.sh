rm bpf_*
echo 'rm go generate'
rm acl
echo 'rm binary'
go generate
go build && sudo ./acl