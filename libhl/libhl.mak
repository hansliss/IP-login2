# Microsoft Developer Studio Generated NMAKE File, Based on libhl.dsp
!IF "$(CFG)" == ""
CFG=libhl - Win32 Debug
!MESSAGE No configuration specified. Defaulting to libhl - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "libhl - Win32 Release" && "$(CFG)" != "libhl - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libhl.mak" CFG="libhl - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libhl - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libhl - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "libhl - Win32 Release"

OUTDIR=.\libhl___Win32_Release
INTDIR=.\libhl___Win32_Release
# Begin Custom Macros
OutDir=.\libhl___Win32_Release
# End Custom Macros

ALL : "$(OUTDIR)\libhl.lib"


CLEAN :
	-@erase "$(INTDIR)\b64.obj"
	-@erase "$(INTDIR)\conffile.obj"
	-@erase "$(INTDIR)\genseed.obj"
	-@erase "$(INTDIR)\hexdump.obj"
	-@erase "$(INTDIR)\hlcrypt.obj"
	-@erase "$(INTDIR)\makeaddress.obj"
	-@erase "$(INTDIR)\md4c.obj"
	-@erase "$(INTDIR)\md5c.obj"
	-@erase "$(INTDIR)\pwdhash.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\rijndael-api-fst.obj"
	-@erase "$(INTDIR)\sha1.obj"
	-@erase "$(INTDIR)\stringfunc.obj"
	-@erase "$(INTDIR)\uu_aes.obj"
	-@erase "$(INTDIR)\varlist.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\libhl.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\libhl.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libhl.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\libhl.lib" 
LIB32_OBJS= \
	"$(INTDIR)\b64.obj" \
	"$(INTDIR)\conffile.obj" \
	"$(INTDIR)\genseed.obj" \
	"$(INTDIR)\hexdump.obj" \
	"$(INTDIR)\hlcrypt.obj" \
	"$(INTDIR)\makeaddress.obj" \
	"$(INTDIR)\md4c.obj" \
	"$(INTDIR)\md5c.obj" \
	"$(INTDIR)\pwdhash.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\rijndael-api-fst.obj" \
	"$(INTDIR)\sha1.obj" \
	"$(INTDIR)\stringfunc.obj" \
	"$(INTDIR)\uu_aes.obj" \
	"$(INTDIR)\varlist.obj"

"$(OUTDIR)\libhl.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "libhl - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\libhl.lib"


CLEAN :
	-@erase "$(INTDIR)\b64.obj"
	-@erase "$(INTDIR)\conffile.obj"
	-@erase "$(INTDIR)\genseed.obj"
	-@erase "$(INTDIR)\hexdump.obj"
	-@erase "$(INTDIR)\hlcrypt.obj"
	-@erase "$(INTDIR)\makeaddress.obj"
	-@erase "$(INTDIR)\md4c.obj"
	-@erase "$(INTDIR)\md5c.obj"
	-@erase "$(INTDIR)\pwdhash.obj"
	-@erase "$(INTDIR)\rijndael-alg-fst.obj"
	-@erase "$(INTDIR)\rijndael-api-fst.obj"
	-@erase "$(INTDIR)\sha1.obj"
	-@erase "$(INTDIR)\stringfunc.obj"
	-@erase "$(INTDIR)\uu_aes.obj"
	-@erase "$(INTDIR)\varlist.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\libhl.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /Fp"$(INTDIR)\libhl.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libhl.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\libhl.lib" 
LIB32_OBJS= \
	"$(INTDIR)\b64.obj" \
	"$(INTDIR)\conffile.obj" \
	"$(INTDIR)\genseed.obj" \
	"$(INTDIR)\hexdump.obj" \
	"$(INTDIR)\hlcrypt.obj" \
	"$(INTDIR)\makeaddress.obj" \
	"$(INTDIR)\md4c.obj" \
	"$(INTDIR)\md5c.obj" \
	"$(INTDIR)\pwdhash.obj" \
	"$(INTDIR)\rijndael-alg-fst.obj" \
	"$(INTDIR)\rijndael-api-fst.obj" \
	"$(INTDIR)\sha1.obj" \
	"$(INTDIR)\stringfunc.obj" \
	"$(INTDIR)\uu_aes.obj" \
	"$(INTDIR)\varlist.obj"

"$(OUTDIR)\libhl.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("libhl.dep")
!INCLUDE "libhl.dep"
!ELSE 
!MESSAGE Warning: cannot find "libhl.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "libhl - Win32 Release" || "$(CFG)" == "libhl - Win32 Debug"
SOURCE=.\b64.c

"$(INTDIR)\b64.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\conffile.c

"$(INTDIR)\conffile.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\genseed.c

"$(INTDIR)\genseed.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\hexdump.c

"$(INTDIR)\hexdump.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\hlcrypt.c

"$(INTDIR)\hlcrypt.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\makeaddress.c

"$(INTDIR)\makeaddress.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\md4c.c

"$(INTDIR)\md4c.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\md5c.c

"$(INTDIR)\md5c.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\pwdhash.c

"$(INTDIR)\pwdhash.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=".\rijndael-alg-fst.c"

"$(INTDIR)\rijndael-alg-fst.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=".\rijndael-api-fst.c"

"$(INTDIR)\rijndael-api-fst.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\sha1.c

"$(INTDIR)\sha1.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\stringfunc.c

"$(INTDIR)\stringfunc.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\uu_aes.c

"$(INTDIR)\uu_aes.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\varlist.c

"$(INTDIR)\varlist.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

