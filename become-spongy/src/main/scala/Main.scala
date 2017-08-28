import java.io.File
import java.time.Instant
import java.time.format.DateTimeFormatter

import com.madgag.git._
import com.madgag.git.bfg.cleaner.protection.ProtectedObjectCensus
import com.madgag.git.bfg.cleaner.{BlobTextModifier, Cleaner, ObjectIdCleaner}
import com.madgag.git.bfg.model.{Commit, CommitArcs, CommitNode, FileName, TreeBlobEntry, TreeSubtrees}
import com.madgag.textmatching.TextReplacementConfig
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.Constants.OBJ_COMMIT
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.revwalk.RevWalk
import org.eclipse.jgit.storage.file.FileRepositoryBuilder

import scalax.io.Resource

object Main extends App {

  val now = Instant.now()

  println(s"Script version: ${app.BuildInfo.version}")

  val runId = DateTimeFormatter.ISO_INSTANT.format(now).replace(':','-')

  val branchName = s"become-spongy_$runId"

  val textReplacementLines = Resource.fromClasspath("text-replacements.txt").lines().filterNot(_.trim.isEmpty).toSeq

  val lineModifier = TextReplacementConfig(textReplacementLines,"").get


  val repo = FileRepositoryBuilder.create(new File("/home/roberto/development/spongycastle/.git"))

  implicit val revWalk = new RevWalk(repo)

  // Package rename org.bouncycastle to org.spongycastle
  private val folderNameFixer:Cleaner[TreeSubtrees] = (subtrees: TreeSubtrees) => TreeSubtrees(subtrees.entryMap.map {
      case (filename, objectId) if filename.string == "bouncycastle" => FileName("spongycastle") -> objectId
      case x => x
    })

  private val textModifier = new BlobTextModifier {

    override val sizeThreshold = 10 * 1024 * 1024 // gotta be bigger than all the text files in BC, ie 1591284 bytes

    def lineCleanerFor(entry: TreeBlobEntry) = if (entry.filename.string.endsWith(".java")) Some(lineModifier) else None

    val threadLocalObjectDBResources = repo.getObjectDatabase.threadLocalResources
  }

  val objectIdCleaner:ObjectIdCleaner =
    new ObjectIdCleaner(ObjectIdCleaner.Config(ProtectedObjectCensus.None,
      treeSubtreesCleaners = Seq(folderNameFixer),
      treeBlobsCleaners = Seq(textModifier)),
      repo.getObjectDatabase, revWalk)

  val mendingBCcommit = repo.resolve("mending-bc").asRevCommit

  val cleanedTree = objectIdCleaner(mendingBCcommit.getTree)

  val personIdent = new PersonIdent(repo)

  val commitMessage =
    s"""|Become spongy with become-spongy BFG script
        |
        |Version: ${app.BuildInfo.version}
        |
        |https://github.com/rtyley/spongycastle/tree/spongy-scripts
        |https://rtyley.github.io/bfg-repo-cleaner/
        |""".stripMargin
  val commitNode = CommitNode(personIdent, personIdent, commitMessage)
  val arcs = CommitArcs(Seq(mendingBCcommit), cleanedTree)
  val cleanedCommit = repo.newObjectInserter().insert(OBJ_COMMIT, Commit(commitNode, arcs).toBytes).asRevCommit
  println(cleanedCommit)

  Git.wrap(repo).checkout().setCreateBranch(true).setName(branchName).setStartPoint(cleanedCommit).call()
  println(branchName)

}
