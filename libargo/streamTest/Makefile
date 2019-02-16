#
# Copyright (c) 2010 Citrix Systems, Inc.
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

CXX=gcc
CXXFLAGS=-c -Wall -I include 
#-DV4V_EXCLUDE_INTERNAL
LDFLAGS=

SOURCES=main.c fileTransfer.c

LIBS=-lv4v -ldl

OBJECTS=$(SOURCES:.c=.o)

EXECUTABLE=fileTester

all: $(SOURCES) $(EXECUTABLE)


$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f *o $(EXECUTABLE)
