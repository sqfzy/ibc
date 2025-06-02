cargo build
if test $status -ne 0
    echo "cargo build failed!"
    exit 1
end

./target/debug/aaka_user_app --user-id testuser@fish.test --server-id testserver.fish.test
