# 提取 BMP 文件的头部信息（通常为 54 个字节）
head -c 54 pic_original.bmp > header

# 检查 BMP 文件的大小
filesize=$(stat -c%s "pic_original.bmp")
padding=$(($filesize % 16))
if [ $padding -ne 0 ]; then
    dd if=/dev/zero bs=1 count=$((16 - $padding)) >> pic_original.bmp
fi

# 加密 BMP 文件（包括头部和填充）
openssl enc -aes-128-cbc -e -in pic_original.bmp -out pic_cbc -K C4A252F9B5CAC1789171026273F2FD98 -iv D2BA62CFD443046D7808FADCB38A47FC

# 分离加密后的文件体并重组 BMP 文件
tail -c +55 pic_cbc > body
cat header body > pic_cbc.bmp