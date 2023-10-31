all:
	swig -I/usr/local/modsecurity/include/ -python -builtin -Wall -Wextra -c++ modsecurity/modsecurity.i
	python setup.py build_ext --inplace

test:
	tests/t.py

install:
	python setup.py install --prefix=/usr

clean:
	@rm modsecurity/modsecurity_wrap.cxx
	@rm -rf build
	@rm _modsecurity.so
	@rm modsecurity/modsecurity.py
	@rm *.pyc tests/*.pyc modsecurity/*.pyc



