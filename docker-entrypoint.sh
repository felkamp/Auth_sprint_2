sh -c "python3 tests/functional/utils/ping.py"
res=$?
if [ $res -eq 0 ]
then
  sh -c "python -m unittest discover tests/functional/test_cases"
fi