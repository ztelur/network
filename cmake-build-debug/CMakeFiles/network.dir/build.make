# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/simu/Work/github/network

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/simu/Work/github/network/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/network.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/network.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/network.dir/flags.make

CMakeFiles/network.dir/socket/simple/server.cpp.o: CMakeFiles/network.dir/flags.make
CMakeFiles/network.dir/socket/simple/server.cpp.o: ../socket/simple/server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/simu/Work/github/network/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/network.dir/socket/simple/server.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/network.dir/socket/simple/server.cpp.o -c /Users/simu/Work/github/network/socket/simple/server.cpp

CMakeFiles/network.dir/socket/simple/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/network.dir/socket/simple/server.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/simu/Work/github/network/socket/simple/server.cpp > CMakeFiles/network.dir/socket/simple/server.cpp.i

CMakeFiles/network.dir/socket/simple/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/network.dir/socket/simple/server.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/simu/Work/github/network/socket/simple/server.cpp -o CMakeFiles/network.dir/socket/simple/server.cpp.s

# Object files for target network
network_OBJECTS = \
"CMakeFiles/network.dir/socket/simple/server.cpp.o"

# External object files for target network
network_EXTERNAL_OBJECTS =

network: CMakeFiles/network.dir/socket/simple/server.cpp.o
network: CMakeFiles/network.dir/build.make
network: CMakeFiles/network.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/simu/Work/github/network/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable network"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/network.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/network.dir/build: network

.PHONY : CMakeFiles/network.dir/build

CMakeFiles/network.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/network.dir/cmake_clean.cmake
.PHONY : CMakeFiles/network.dir/clean

CMakeFiles/network.dir/depend:
	cd /Users/simu/Work/github/network/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/simu/Work/github/network /Users/simu/Work/github/network /Users/simu/Work/github/network/cmake-build-debug /Users/simu/Work/github/network/cmake-build-debug /Users/simu/Work/github/network/cmake-build-debug/CMakeFiles/network.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/network.dir/depend

