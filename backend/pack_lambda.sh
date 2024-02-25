mkdir lambda_dir
cp lambda_function.py lambda_dir
cp test_walker.py lambda_dir
cp requirements.txt lambda_dir
cp proompt.py lambda_dir
cp -r context lambda_dir
cd lambda_dir
pip install -r requirements.txt -t .
zip fuzz_guard.zip *
mv fuzz_guard.zip ../
cd ..
rm -rf lambda_dir
