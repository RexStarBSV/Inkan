// Inkan — Kotlin reference implementation + conformance gate.
//
// Run the parity gate with:   ./gradlew test     (from Inkan/kotlin/)
// or point at the vectors explicitly:
//   INKAN_VECTORS=/path/to/seal-v3-vectors.json ./gradlew test
//
// The engine itself (SealV3.kt, SealTables.kt) has NO third-party dependencies — only the JDK
// standard library (MessageDigest, Base64, CRC32, Deflater). Everything below is test-only, and
// exists solely to read the canonical vector JSON. Keep it that way: a 100-year reference
// implementation should not be able to rot because a dependency did.
plugins {
    kotlin("jvm") version "1.9.24"
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}

kotlin {
    // Pinned to the toolchain the conformance run is recorded against (Temurin 17).
    jvmToolchain(17)
}
