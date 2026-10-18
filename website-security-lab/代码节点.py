# coding=utf-8
from runtime import Args
import uuid
import json
import os

def handler(args: Args) -> dict:

    # 使用"args.input.变量名"可以获取代码节点输入参数的具体参数值，示例如下：
    # a = args.input.a
    # b = args.input.b

    # 当输入参数为文件，需要在代码节点中获取该文件的内容，示例如下：
    # fb = FileBucket() # 根据节点提供的SDK方法，实例化一个FileBucket对象
    # filename = args.input.filename # 获取需要读取的文件名
    # byte_stream = fb.get(filename) # 通过get方法获取到文件流，后续可根据实际需要对文件流进行处理

    # 当代码节点中生成一个文件需要保存输出，示例如下：
    # fb = FileBucket() # 根据节点提供的SDK方法，实例化一个FileBucket对象
    # filename = fb.save('results.xlsx',binary_data) # 通过save方法将文件流写入到对应的文件中并保存

    # 调用大模型接口-方法一（推荐使用）
    # from openai import OpenAI
    # client = OpenAI()
    # response1 = client.chat.completions.create(
    #     model = "HengNao-v4",
    #     temperature = 0.7,
    #     max_tokens = 1024,
    #     top_p = 1, 
    #     extra_body = {
    #         "top_k": -1  
    #     },
    #     messages = [
    #        { "role": "user", "content": "你好" }
    #     ]
    # )
    # print(response1.choices[0].message.content)

    # 调用大模型接口-方法二
    # from langchain_openai import ChatOpenAI
    # from langchain_core.messages import HumanMessage

    # llm = ChatOpenAI(
    #     model="HengNao-v4",
    # )
    # response2 = llm.invoke([
    #     HumanMessage(content="你好")
    # ])

    # 在代码节点运行过程中临时写入文件内容
    # with open('1.txt','w') as f:
    #     f.write("xxxxxxxxxxxx")

    # 在代码节点运行过程中临时读取文件内容
    # with open('1.txt','r') as f:
    #     result = f.readline()

    # return {
    #     'response1': response1,
    #     'response2': response2,
    # }
