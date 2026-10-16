#!/usr/bin/env ruby
# frozen_string_literal: true

# Adds the JanVaani iOS extensions (SMS message filter, caller labels) to the Xcode project
# that `expo prebuild` generates, and embeds them in the app. Run it from packages/mobile
# after prebuild and before `pod install`:
#
#   ruby ios-extensions/add_extensions.rb
#
# Needs the `xcodeproj` gem, which ships with CocoaPods.

require 'fileutils'
require 'xcodeproj'

ROOT = File.expand_path(__dir__)
IOS_DIR = File.expand_path('../ios', ROOT)
DEPLOYMENT_TARGET = '15.1'

EXTENSIONS = [
  {
    name: 'MessageFilter',
    suffix: 'MessageFilter',
    sources: ['MessageFilter/MessageFilterExtension.swift', 'Shared/ScamRules.swift'],
    resources: [],
    plist: 'MessageFilter/Info.plist'
  },
  {
    name: 'CallDirectory',
    suffix: 'CallDirectory',
    sources: ['CallDirectory/CallDirectoryHandler.swift'],
    resources: ['CallDirectory/scam-numbers.txt'],
    plist: 'CallDirectory/Info.plist'
  }
].freeze

project_path = Dir.glob(File.join(IOS_DIR, '*.xcodeproj')).first
abort("No .xcodeproj found in #{IOS_DIR}. Run `npx expo prebuild --platform ios` first.") unless project_path

project = Xcodeproj::Project.open(project_path)
app_target = project.targets.find { |t| t.product_type == 'com.apple.product-type.application' }
abort('No application target found.') unless app_target

app_bundle_id = app_target.build_configurations.first.build_settings['PRODUCT_BUNDLE_IDENTIFIER']
abort('Could not read the app bundle identifier.') if app_bundle_id.nil? || app_bundle_id.empty?

embed_phase = app_target.copy_files_build_phases.find { |p| p.name == 'Embed Foundation Extensions' }
embed_phase ||= app_target.new_copy_files_build_phase('Embed Foundation Extensions')
embed_phase.symbol_dst_subfolder_spec = :plug_ins

EXTENSIONS.each do |ext|
  next if project.targets.any? { |t| t.name == ext[:name] }

  # Copy the extension sources next to the Xcode project so paths stay relative to ios/.
  dest = File.join(IOS_DIR, ext[:name])
  FileUtils.mkdir_p(dest)
  (ext[:sources] + ext[:resources] + [ext[:plist]]).each do |rel|
    FileUtils.cp(File.join(ROOT, rel), File.join(dest, File.basename(rel)))
  end

  target = project.new_target(:app_extension, ext[:name], :ios, DEPLOYMENT_TARGET)
  group = project.main_group.new_group(ext[:name], ext[:name])

  source_refs = ext[:sources].map { |rel| group.new_reference(File.basename(rel)) }
  target.add_file_references(source_refs)

  ext[:resources].each do |rel|
    ref = group.new_reference(File.basename(rel))
    target.resources_build_phase.add_file_reference(ref, true)
  end
  group.new_reference(File.basename(ext[:plist]))

  target.build_configurations.each do |config|
    config.build_settings.merge!(
      'PRODUCT_BUNDLE_IDENTIFIER' => "#{app_bundle_id}.#{ext[:suffix]}",
      'PRODUCT_NAME' => ext[:name],
      'INFOPLIST_FILE' => "#{ext[:name]}/#{File.basename(ext[:plist])}",
      'SWIFT_VERSION' => '5.0',
      'IPHONEOS_DEPLOYMENT_TARGET' => DEPLOYMENT_TARGET,
      'TARGETED_DEVICE_FAMILY' => '1,2',
      'SKIP_INSTALL' => 'YES',
      'CODE_SIGN_STYLE' => 'Automatic',
      'GENERATE_INFOPLIST_FILE' => 'NO',
      'LD_RUNPATH_SEARCH_PATHS' => '$(inherited) @executable_path/Frameworks @executable_path/../../Frameworks',
      'APPLICATION_EXTENSION_API_ONLY' => 'YES'
    )
  end

  app_target.add_dependency(target)
  build_file = embed_phase.add_file_reference(target.product_reference, true)
  build_file.settings = { 'ATTRIBUTES' => %w[RemoveHeadersOnCopy] }
end

project.save
puts "Added extensions to #{File.basename(project_path)}: #{EXTENSIONS.map { |e| e[:name] }.join(', ')}"
