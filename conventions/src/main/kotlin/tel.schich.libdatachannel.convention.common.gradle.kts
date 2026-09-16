plugins {
    `java-library`
    signing
    `maven-publish`
}

group = "dev.opencollab"

java {
    withSourcesJar()
    withJavadocJar()

    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.compileJava {
    options.release = 11
    javaCompiler = javaToolchains.compilerFor {
        languageVersion = JavaLanguageVersion.of(11)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:deprecation",
            "-Xlint:unchecked",
        )
    )
}

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    compileOnly(libs.jdtAnnotations)
    implementation(libs.slf4j)

    testImplementation(libs.junitJupiter)
    testRuntimeOnly(libs.junitPlatformLauncher)
    testImplementation(libs.logbackClassic)
}

publishing {
    repositories {
        // Temporary fork snapshots use the workflow's repository-scoped token.
        // Canonical OpenCollab publishing remains unchanged.
        if (System.getenv("GITHUB_REPOSITORY") == "teamziax/libdatachannel-java") {
            maven {
                name = "githubPackages"
                url = uri("https://maven.pkg.github.com/teamziax/libdatachannel-java")
                credentials(PasswordCredentials::class)
            }
        }
        maven {
            name = Constants.SNAPSHOTS_REPO
            url = uri("https://repo.opencollab.dev/maven-snapshots/")
            credentials(PasswordCredentials::class)
        }
        maven {
            name = Constants.RELEASES_REPO
            url = uri("https://repo.opencollab.dev/maven-releases/")
            credentials(PasswordCredentials::class)
        }
    }

    publications {
        register<MavenPublication>("maven") {
            artifactId = project.name
            from(components["java"])

            pom {
                name = artifactId
                description = project.description
                url = "https://github.com/opencollab-incubator/libdatachannel-java"
                licenses {
                    license {
                        name = "MIT"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                developers {
                    developer {
                        id.set("pschichtel")
                        name.set("Phillip Schichtel")
                        email.set("phillip@schich.tel")
                    }
                    developer {
                        id.set("faithcaio")
                    }
                }
                scm {
                    url.set("https://github.com/opencollab-incubator/libdatachannel-java")
                    connection.set("scm:git:https://github.com/opencollab-incubator/libdatachannel-java")
                    developerConnection.set("scm:git:git@github.com:opencollab-incubator/libdatachannel-java")
                }
            }
        }
    }
}

// A restored fork must never overwrite the canonical artifact coordinates.
tasks.withType<PublishToMavenRepository>().configureEach {
    doFirst {
        if (repository.name == "githubPackages" &&
            !project.version.toString().matches(Regex("""[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-teamziax-connectivity-[a-f0-9]{12}-SNAPSHOT"""))) {
            throw GradleException("GitHub publication requires a source-qualified TeamZiax snapshot version")
        }
    }
}

private val signingKey = System.getenv("SIGNING_KEY")?.ifBlank { null }?.trim()
private val signingKeyPassword = System.getenv("SIGNING_KEY_PASSWORD")?.ifBlank { null }?.trim() ?: ""

when {
    signingKey != null -> {
        logger.lifecycle("Received a signing key, using in-memory pgp keys!")
        signing {
            useInMemoryPgpKeys(signingKey, signingKeyPassword)
            sign(publishing.publications)
        }
    }
    !Constants.CI -> {
        logger.lifecycle("Not running in CI, using the gpg command!")
        signing {
            useGpgCmd()
            sign(publishing.publications)
        }
    }
    else -> {
        logger.lifecycle("Not signing artifacts!")
    }
}
