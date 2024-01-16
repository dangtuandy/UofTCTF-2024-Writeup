## Challange
### Secret Message 1
* ![Screenshot 2024-01-15 141301](https://hackmd.io/_uploads/HyySnnzKT.png)
**Giải pháp:**
* Ta tiến hành download file .pdf này về , mở lên:
* ![Screenshot 2024-01-15 211001](https://hackmd.io/_uploads/rJQ02hfYT.png)
, Đoạn flag bị che trong phần màu đen này và bôi đen copy thì có được flag
**Flag:** *uoftctf{fired_for_leaking_secrets_in_a_pdf}*
### EnableMe
* ![Screenshot 2024-01-15 141602](https://hackmd.io/_uploads/H1b00nzta.png)
**Giải pháp:**
* Đây là một file `microsoft word 2007+`, mình tiến hành mở lên thì có 1 ảnh bị mờ không thấy được nội dung gì, theo như mô tả là `unclock it` và file này `không chứa mã độc` .
* Tiếp theo thì em xem mã hex file này thì thấy có rất nhiều file và thư mục bên trong nên mình đã unzip và cũng có 1 ảnh .png bên trong thư mục của file vừa extract và mình đã dùng rất nhiều tool về stego nhưng chả có gì và rồi mình đã bị lừa bởi author vì khi post file `.docm` lên [virustotal](https://www.virustotal.com/), thì thấy có chứa nhiều mã độc nên mình đã dùng tool `olevba` để phân tích :
![Screenshot 2024-01-15 212929](https://hackmd.io/_uploads/H1b6MTft6.png)
, ta thấy có đoạn mã macro và muốn chi tiết hơn hãy nhìn bảng ở dưới thì biết được đoạn mã trên đang thực hiện phép xor giữa v6,v7,v8 và mình viết 1 đoạn script bằng python để thực hiện lại:
```
v6=[98, 120, 113, 99, 116, 99, 113, 108, 115, 39, 116, 111, 72, 113, 38, 123, 36, 34, 72, 116, 35, 121, 72, 101, 98, 121, 72, 116, 39, 115, 114, 72, 99, 39, 39, 39, 106]
v7=[44, 32, 51, 84, 43, 53, 48, 62, 68, 114, 38, 61, 17, 70, 121, 45, 112, 126, 26, 39, 21, 78, 21, 7, 6, 26, 127, 8, 89, 0, 1, 54, 26, 87, 16, 10, 84]
v8=23
#v9=v6^v8
v9=[i6^v8 for i6 in v6] 
#v10=v7^v9
v10=[i7^v9[index%len(v9)]  for index,i7 in enumerate(v7)]
#in ra dạng ascii và ghép lại của v9 và v10
result_v9=''.join(chr(i) for i in v9) # cho i duyệt qua các phần tử trong list v9 và bỏ vào phương thức ''.join() để ghép thành 1 chuỗi ascii.
print(result_v9)
result_v10=''.join(chr(i) for i in v10) # cho i duyệt qua các phần tử trong list v10 và bỏ vào phương thức ''.join() để ghép thành 1 chuỗi ascii.
print(result_v10)
```
,chạy đoạn code trên ta được :

![Screenshot 2024-01-16 112521](https://hackmd.io/_uploads/BJmjHKmta.png)
,1 đoạn flag là của `result_v9` và đoạn chữ lại của `result_v10` 

**Flag:** *uoftctf{d0cx_f1l35_c4n_run_c0de_t000}*

### Hourglass + No Grep
* ![Screenshot 2024-01-15 143306](https://hackmd.io/_uploads/Sys4rpzFp.png)
* ![Screenshot 2024-01-15 143242](https://hackmd.io/_uploads/Byf8STzK6.png)
* **Note:** vì 2 bài này liên quan nhau nên mình xin phép gộp chung lại.
* Sau khi download file (9.2GB) này về thì extract ra được 1 file `.ova(Open Virtualization Appliance) : hiểu nôm na là .ova là một gói đóng gói chứa toàn bộ dữ liệu của một máy ảo, cho phép dễ dàng chia sẻ và triển khai máy ảo trên các nền tảng ảo hóa khác nhau`, để mở được thì mình dùng tool `FTK imager` để trích ra 1 file `vm:ctf_vm-disk001` , tiếp theo đó mình ném lên tool `autopsy` để phân tích.
* Thì đầu tiên thì mình luôn luôn vào phần `web history` để check xem thử đã có những file nào được tạo hoặc xóa ở khoảng thời gian trước đó:
* ![Screenshot 2024-01-15 220021](https://hackmd.io/_uploads/Sk4ZFpGFp.png)
,thì ta thấy ở đây có rất nhiều path khác nhau như ta chỉ để ý đến những cái path có `.txt` và có 1 file rất đặc biệt là file `.ps1:là 1 file powershell mà hacker thường dùng để chạy, phát tán mã độc trên máy victim ở OS Windows` , à lúc này ta thấy có 1 file tên `flag.txt` mò theo đường dẫn thì ta có được 1 flag fake =))) `uoftctf{fake_flag_lol}`
, ta tiếp tục check đến các file mà nghi ngờ từ trước kia thì có 1 file tên `settings.txt` nằm với path `file:///C:/Windows/DiagTrack/Settings/settings.txt` thì có 1 đoạn chuỗi nhìn rất đáng ngờ nên mình ném lên [cyberchef](https://gchq.github.io/CyberChef/) để decode thì:
* ![Screenshot 2024-01-16 114111](https://hackmd.io/_uploads/S1WLFtmKT.png)
ra được flag thì thử submit thì flag này là của bài **Hourglass** 
**Flag:** *uoftctf{T4sK_Sch3Dul3r_FUN}*

* Ta tiếp tục check đến file powshell với path là `file:///C:/Windows/Web/Wallpaper/Theme2/update.ps1` thì có được 1 đoạn code như này:
```
$String_Key = 'W0wMadeitthisfar'

$NewValue = '$(' + (([int[]][char[]]$String | ForEach-Object { "[char]$($_)" }) -join '+') + ')'

$chars = 34, 95, 17, 57, 2, 16, 3, 18, 68, 16, 12, 54, 4, 82, 24, 45, 35, 0, 40, 63, 20, 10, 58, 25, 3, 65, 0, 20

$keyAscii = $String_Key.ToCharArray() | ForEach-Object { [int][char]$_ }

$resultArray = $chars -bxor $keyAscii
```
mới nhìn vào thì thấy nó rối nhưng ngồi phân tích 1 lúc thì đoạn code này đại khái là decode cái `string_key` kia sang hệ dec(10) rồi xor với `chars` , mình sẽ tiến hành viết 1 đoạn script:
```
string_key = "W0wMadeitthisfar"
chars=[34,95,17,57,2, 16, 3, 18, 68, 16, 12, 54, 4, 82, 24, 45, 35, 0, 40, 63, 20, 10, 58, 25, 3, 65, 0, 20
]
dec_key=[ord(i) for i in string_key] #decode từ ascii sang 1 list số hệ 10
result_array=[char ^ dec_key[index%len(dec_key)] for index , char in enumerate(chars)] #xor 2 list chars và dec_key
result=''.join(chr(i) for i in result_array) # dùng phương thức join để ghép các kí tự ascii từ tham số bên trong 
print(result)
```
sau khi chạy đoạn python này thì ta có được flag của bài **No Grep**
**Flag:** *uoftctf{0dd_w4y_t0_run_pw5h}*


  
