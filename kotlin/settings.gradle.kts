// The Kotlin reference implementation of the Inkan seal standard is a standalone, plain-JVM
// project: it unit-tests against the canonical vectors on any JVM, with no Android SDK and no
// other repository required. That self-containment is the point — the standard carries its own proof.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "inkan-kotlin"
