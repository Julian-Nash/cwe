VENV=venv
ACTIVATE?=. ${VENV}/bin/activate;
valid:
	isort black .

black:
	@echo "-> Apply black code formatter"
	${VENV}/bin/black .

dev:
	echo "-> Configure virtual environment and install development dependencies"
	python3 -m venv venv
	@${ACTIVATE} pip install -r requirements.txt