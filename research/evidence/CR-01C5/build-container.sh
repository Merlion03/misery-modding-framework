#!/usr/bin/env bash
# Build the MBPLTest mod container from the cooked mod content ONLY.
#
# Two things are deliberate here:
#   * Engine content and the shader archives are moved OUT of the cook tree
#     before the container is built. CR-01C4B established that a mod container
#     carrying ShaderArchive-Global-* / ShaderArchive-MISERY-* shadows the
#     game's own shader libraries at the higher mount priority.
#   * The IoStore response file is written explicitly, one line per package, so
#     what goes into the container is enumerated rather than swept up.
set -u
KIT="D:/UEScratch/MBPLKit"
COOKED="$KIT/Saved/Cooked/Windows"
OUT="$KIT/out"
PRUNED="$KIT/_pruned"
UPAK="D:/Program Files/UE_5.4/Engine/Binaries/Win64/UnrealPak.exe"
STAGE="C:/Users/Anton/AppData/Local/MISERY/Saved/Paks"

echo "== prune Engine content and shader archives out of the cook tree =="
mkdir -p "$PRUNED"
if [ -d "$COOKED/Engine" ]; then
  rm -rf "$PRUNED/Engine"
  mv "$COOKED/Engine" "$PRUNED/Engine"
  echo "   moved Engine/ -> _pruned/"
fi
mkdir -p "$PRUNED/shaders"
for f in "$COOKED/MISERY/Content"/ShaderArchive-* "$COOKED/MISERY/Content"/ShaderAssetInfo-*; do
  [ -e "$f" ] || continue
  mv "$f" "$PRUNED/shaders/" && echo "   moved $(basename "$f") -> _pruned/shaders/"
done

echo "== what remains in the cook tree that could be containerised =="
find "$COOKED" -type f | sed "s|$COOKED/||" | sort

echo "== write the IoStore response file (explicit, one line per package) =="
: > "$OUT/response.txt"
for p in SM_MBPL_Radio T_MBPL_Radio_Icon; do
  for ext in uasset uexp ubulk; do
    src="$COOKED/MISERY/Content/MBPLTest/Items/Radio/$p.$ext"
    [ -f "$src" ] || continue
    echo "\"$src\" \"../../../MISERY/Content/MBPLTest/Items/Radio/$p.$ext\"" >> "$OUT/response.txt"
  done
done
cat "$OUT/response.txt"

echo "== build the IoStore container =="
rm -f "$OUT/containers"/MBPLTest.utoc "$OUT/containers"/MBPLTest.ucas
"$UPAK" \
  -CreateGlobalContainer="$OUT/containers/global.utoc" \
  -CookedDirectory="$COOKED" \
  -Commands="$OUT/commands.txt" \
  -ScriptObjects="$COOKED/MISERY/Metadata/scriptobjects.bin" \
  -PackageStoreManifest="$COOKED/MISERY/Metadata/packagestore.manifest" \
  > "$KIT/out_iostore_mesh.log" 2>&1
echo "   iostore exit: $?"
tail -3 "$KIT/out_iostore_mesh.log"

echo "== build the .pak carrying the modinfo =="
"$UPAK" "$OUT/containers/MBPLTest_P.pak" -create="$OUT/pak_response.txt" \
  > "$KIT/out_pak_mesh.log" 2>&1
echo "   pak exit: $?"

ls -la "$OUT/containers/"
