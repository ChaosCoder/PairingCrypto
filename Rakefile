require 'rake'

flags = "-Xlinker -L/usr/local/lib -Xswiftc -I/usr/local/include"

desc "Generate Xcode project"
task :gen_xcodeproj do
  sh "swift package generate-xcodeproj --xcconfig-overrides settings.xcconfig"
end

desc "Fetch swift packages"
task :fetch do
  sh "swift package fetch"
end

desc "Run tests"
task :test => :fetch do
  sh "swift test #{flags}"
end

desc "Build using config"
task :build, [:config] => :fetch do |t, args|
  args.with_defaults(config: "debug")
  sh "swift build #{flags} -c #{args[:config]}"
end

task :clean => :remove_packages do
  sh "swift build --clean"
end

task :remove_packages do
  sh "rm -rf Packages/"
end
