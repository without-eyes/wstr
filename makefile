# Compiler and flags
CC = gcc
CFLAGS = -Wall -I$(IDIR) -g

# Directories
IDIR = ./include/
SRCDIR = ./src/

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(SRCDIR)/%.o)

# Output binary
TARGET = wstr

# Main targets
all: $(TARGET)

# Rule for compiling the target
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -o $(TARGET)

# Rule for compiling source files into object files
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for deleting object and binary files
clean:
	rm -f $(SRCDIR)/*.o $(TARGET)