package org.whispersystems.witness

import org.gradle.api.InvalidUserDataException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.ResolvedArtifact

import java.security.MessageDigest

class WitnessPluginExtension {
    List verify
    List includedConfigurations
}

class WitnessPlugin implements Plugin<Project> {

    static String calculateSha256(file) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        file.eachByte 4096, {bytes, size ->
            md.update(bytes, 0, size);
        }
        return md.digest().collect {String.format "%02x", it}.join();
    }

    void apply(Project project) {
        project.extensions.create("dependencyVerification", WitnessPluginExtension)
        project.dependencyVerification.includedConfigurations = [project.configurations.compile]
        project.afterEvaluate {
            String failedChecksumsError = ""
            project.dependencyVerification.verify.each {
                assertion ->
                    List  parts  = assertion.tokenize(":")
                    String group = parts.get(0)
                    String name  = parts.get(1)
                    String hash  = parts.get(2)

                    ResolvedArtifact dependency
                    project.dependencyVerification.includedConfigurations.find{
                        dependency = it.resolvedConfiguration.resolvedArtifacts.find {
                             return it.name.equals(name) && it.moduleVersion.id.group.equals(group)
                        }
                    }

                    println "Verifying " + group + ":" + name

                    if (dependency == null) {
                        throw new InvalidUserDataException("No dependency for integrity assertion found: " + group + ":" + name)
                    }

                    String calculatedHash = calculateSha256(dependency.file)
                    if (!hash.equals(calculatedHash)) {
                        failedChecksumsError += "Checksum failed for " + assertion + "\ncalculated checksum: " + calculatedHash + "\n\n"
                    }
            }
            if (failedChecksumsError != "") {
                throw new InvalidUserDataException(failedChecksumsError)
            }
        }

        project.task('calculateChecksums') << {
            println "dependencyVerification {"
            println "    verify = ["

            project.dependencyVerification.includedConfigurations.each {
                conf ->
                    println "        "
                    println "        // " + conf.name
                    conf.resolvedConfiguration.resolvedArtifacts.sort{
                      a, b -> a.moduleVersion.id.group <=> b.moduleVersion.id.group ?: a.name <=> b.name
                    }.each {
                        dep ->
                            println "        '" + dep.moduleVersion.id.group+ ":" + dep.name + ":" + calculateSha256(dep.file) + "',"
                    }
            }

            println "    ]"
            println "}"
        }
    }
}
