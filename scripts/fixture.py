from pathlib import Path
import os,subprocess
HERE=Path(__file__).resolve().parent
OUT=HERE.parent/'build'
GRADLE=None
def write(path,text):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
def build():
 if not os.environ.get('PUBLISHED_BOOTSTRAP'):
  subprocess.run([str(HERE.parent/'gradlew'),'--no-daemon','check','publishAllPublicationsToFixtureRepository'],cwd=HERE.parent,check=True)
 public=OUT/'public'
 if not public.exists():public.symlink_to(OUT/'repository',target_is_directory=True)
