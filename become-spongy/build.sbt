scalaVersion := "2.11.11"

libraryDependencies ++= Seq(
  "com.madgag" %% "scala-textmatching" % "2.3",
  "com.madgag" %% "bfg-library" % "1.12.15"
)

import scala.sys.process._

lazy val root = (project in file(".")).enablePlugins(
  BuildInfoPlugin
).settings(
  buildInfoKeys := Seq[BuildInfoKey](
    name,
    BuildInfoKey.action("version") {
      try {
        "git describe --all --always --dirty --long".!!.trim
      } catch { case e: Exception => "unknown" }
    }
  ),
  buildInfoPackage := "app"
)
