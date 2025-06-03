# 获取所有包含Makefile的子目录
SUBDIRS = $(shell find . -mindepth 1 -maxdepth 1 -type d -exec test -f {}/Makefile \; -print)

BIN_DIR := ./bin
# 确保目录存在
$(shell mkdir -p $(BIN_DIR))

# 定义默认目标
.PHONY: all ${SUBDIRS} clean

$(info Found subdirectories: $(SUBDIRS))

all: $(SUBDIRS)
	@echo "Build completed in all subdirectories"



# 遍历子目录执行make
$(SUBDIRS):
	@echo "Building in: $@"
	$(MAKE) -C $@

# 清理所有子目录
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done
