let original_dir = (pwd)

# 1. 运行aaka_rc_app

cd $env.FILE_PWD
cd ./aaka_rc_app


try {
  print $"Building aaka_rc_app"
  RUSTFLAGS="-A warnings" cargo build 
} catch {
  print "Failed to build aaka_rc_app"
  exit 1
}

# 取出nodes中的每个地址，然后设置RC_ADDR环境变量并运行
let nodes = open "config.json" | get nodes

print $"Running aaka_rc_app on nodes: ($nodes)"

let master_rc = $nodes.0


$nodes | each { |rc_addr|
  with-env { RC_ADDR: $rc_addr, LOG_LEVEL: "debug" } {
    job spawn { RUSTFLAGS="-A warnings" cargo run }
  }
}

# 发送POST请求到master_rc的/setup端点
try {
  print $"Setting up master RC at ($master_rc)"
  ^http get $"http://($master_rc)/setup"
} catch {
  print "Failed to setup master RC at $master_rc"
  exit 1
}
print $"Setup master RC at ($master_rc)"

# 2. 运行aaka_ms_server

cd $env.FILE_PWD
cd ./aaka_ms_server

try {
  print "Building aaka_ms_server"
  RUSTFLAGS="-A warnings" cargo build 
} catch {
  print "Failed to build aaka_ms_server"
  exit 1
}
job spawn { RUSTFLAGS="-A warnings" cargo run }

# 3. 运行aaka_user_app

cd $env.FILE_PWD
cd ./aaka_user_app

try {
  print "Running aaka_user_app"
  RUSTFLAGS="-A warnings" cargo run
} catch {
  print "Failed to run aaka_user_app"
  exit 1
}

# 4. clean up jobs
job list | get id | each { |job_id|
  print $"Killing job with ID: ($job_id)"
  job kill $job_id
}

# 5. 返回原始目录
cd $original_dir
