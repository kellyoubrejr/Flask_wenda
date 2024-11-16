import qrcode

img = qrcode.make('http://www.baidu.com')

img.save('baidu.png')

def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(0, n-i-1):
            if arr[j] > arr[j+1]:
                arr[j], arr[j+1] = arr[j+1], arr[j]

# 测试冒泡排序
arr = [64, 34, 25, 12, 22, 11, 90]
bubble_sort(arr)
print("排序后的数组: ", arr)

import os

# 获取当前工作目录
cwd = os.getcwd()
print("当前工作目录: ", cwd)

import pandas as pd

# 创建数据框
data = {
    "Name": ["Alice", "Bob", "Charlie"],
    "Age": [25, 30, 35],
    "City": ["New York", "Los Angeles", "Chicago"]
}
df = pd.DataFrame(data)
print(df)


# import matplotlib.pyplot as plt
#
# # 创建数据
# x = [1, 2, 3, 4, 5]
# y = [10, 20, 25, 30, 40]
#
# # 绘制折线图
# plt.plot(x, y)
# plt.xlabel("X 轴")
# plt.ylabel("Y 轴")
# plt.title("简单折线图")
# plt.show()




# import turtle as t
#
# t.setup(width=800, height=600)
# t.title('爱心')
# t.speed(3)
# t.color("red")
# t.pensize(3)
#
# t.begin_fill()
# t.left(50)
# t.forward(133)
# t.circle(50, 200)
# t.right(140)
# t.circle(50, 200)
# t.forward(133)
# t.end_fill()
#
# t.hideturtle()
#
# t.done()



















