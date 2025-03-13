CC = gcc
EXT = c

OPT =
DBG =
WARNINGS = -Wall -Wextra -Wsign-conversion -Wconversion

INC_DIRS = ./include/
INCS = $(foreach DIR,$(INC_DIRS),-I$(DIR))

CFLAGS = $(DBG) $(OPT) $(INCS) $(WARNINGS)

BUILD_DIR = ./build
CODE_DIR = ./src

SRC = $(shell find $(CODE_DIR) -name '*.$(EXT)')
OBJ = $(addprefix $(BUILD_DIR)/,$(notdir $(SRC:.$(EXT)=.o)))

PROJ = wstr
EXEC = $(PROJ)

all: $(BUILD_DIR)/$(EXEC)
	@echo "========================================="
	@echo "              BUILD SUCCESS              "
	@echo "========================================="

release: OPT += -O2
release: all

debug: DBG += -g -gdwarf-2
debug: all

$(BUILD_DIR)/%.o: $(CODE_DIR)/%.$(EXT) | $(BUILD_DIR)
	$(CC) -c $< -o $@ $(CFLAGS)

$(BUILD_DIR)/$(EXEC): $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all release debug clean