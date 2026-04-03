#!/data/data/com.termux/files/usr/bin/bash

echo "=============================="
echo "      🍁 枫叶社区状态 🍁"
echo "=============================="

# 后端服务
if pgrep -f "python.*backend.py" > /dev/null; then
    echo "✅ 后端服务 (backend.py) 运行中"
else
    echo "❌ 后端服务未运行"
fi

# PostgreSQL 数据库
if pgrep -f "postgres" > /dev/null; then
    echo "✅ PostgreSQL 数据库运行中"
else
    echo "❌ PostgreSQL 未运行"
fi

# Serveo 隧道
if pgrep -f "ssh.*serveo" > /dev/null; then
    echo "✅ Serveo 隧道运行中"
else
    echo "❌ Serveo 隧道未运行"
fi

# Ollama 模型服务（如果需要）
if pgrep -f "ollama" > /dev/null; then
    echo "✅ Ollama 模型服务运行中"
else
    echo "❌ Ollama 模型服务未运行"
fi

echo "------------------------------"
echo "后端端口: 8083"
echo "公网域名: https://liuhuaichen.serveousercontent.com"
echo "------------------------------"

# 内存使用情况（可选）
echo "内存使用："
free -h | grep -E "Mem|Swap"

echo "=============================="
