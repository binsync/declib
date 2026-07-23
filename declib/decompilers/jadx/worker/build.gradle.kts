import org.gradle.api.tasks.Copy
import org.gradle.jvm.tasks.Jar

plugins {
    application
    java
}

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation("io.github.skylot:jadx-core:1.5.6")
    implementation("com.google.code.gson:gson:2.14.0")
    implementation("org.slf4j:slf4j-simple:2.0.18")

    runtimeOnly("io.github.skylot:jadx-dex-input:1.5.6")
    runtimeOnly("io.github.skylot:jadx-java-input:1.5.6")
    runtimeOnly("io.github.skylot:jadx-smali-input:1.5.6")
    runtimeOnly("io.github.skylot:jadx-aab-input:1.5.6")
    runtimeOnly("io.github.skylot:jadx-xapk-input:1.5.6")

    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("declib.jadxworker.Main")
    applicationName = "declib-jadx-worker"
    applicationDefaultJvmArgs = listOf(
        "-Xms128m",
        "-Xmx4g",
        "-XX:+UseG1GC",
    )
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

tasks.withType<Jar>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.register<Copy>("stageBridge") {
    dependsOn(tasks.jar)
    from(tasks.jar.flatMap { it.archiveFile })
    into(layout.projectDirectory.dir("bridge"))
    rename { "declib-jadx-worker.jar" }
}

tasks.test {
    useJUnitPlatform()
}
