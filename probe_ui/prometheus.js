const { Kafka } = require('kafkajs');
const express = require('express');
const promClient = require('prom-client');

const app = express();

// Create Prometheus Metrics
const createGauge = (name, help, labelNames = []) => new promClient.Gauge({ name, help, labelNames });

const metrics = {
    packetCount: createGauge('kafka_pid_packet_count', 'Packet count per PID', ['dst', 'pid']),
    ccErrors: createGauge('kafka_pid_cc_errors', 'CC errors per PID', ['dst', 'pid']),
    mbps: createGauge('kafka_pid_mbps', 'Mbps per PID', ['dst', 'pid']),
    statsMpbs: createGauge('kafka_stats_mbps', 'Mbps from stats', ['dst']),
    la1: createGauge('kafka_la1', 'Load Average 1 minute', ['dst']),
    iat1Min: createGauge('kafka_iat1_min', 'Minimum IAT1', ['dst']),
    iat1Max: createGauge('kafka_iat1_max', 'Maximum IAT1', ['dst']),
    iat1Avg: createGauge('kafka_iat1_avg', 'Average IAT1', ['dst']),
    // ... Additional metrics definitions ...
};

// Kafka Consumer and Metrics Updater
const run = async () => {
    const serviceStreamCount = createGauge('kafka_service_stream_count', 'Number of streams per service', ['dst', 'service_index']);
    const kafka = new Kafka({ clientId: 'test', brokers: ['sun:9092'] });
    const consumer = kafka.consumer({ groupId: 'prometheus' });
    await consumer.connect();
    await consumer.subscribe({ topic: 'test', fromBeginning: false });

    await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
            try {
                let messageStr = message.value.toString();
    
                // Validate and Clean Message
                if (messageStr.indexOf('^posting html json:$') === 0) {
                    messageStr = messageStr.substring(20);
                }
                if (!messageStr || !messageStr.trim() || !isJson(messageStr)) {
                    console.error('Invalid message:', messageStr);
                    return;
                }
    
                const data = JSON.parse(messageStr);
                const dst = data.dst.replace(':', '_');
    
                // Check if pids is defined and is an array
                if (Array.isArray(data.pids)) {
                    // Update PID Metrics
                    data.pids.forEach(pidData => {
                        ['packetCount', 'ccErrors', 'mbps'].forEach(metric => {
                            metrics[metric].labels(dst, pidData.pid).set(pidData[metric.toLowerCase()]);
                        });
                    });
                } else {
                    console.error('Invalid or missing pids:', data.pids);
                }
    
                // Update Stats Metrics
                metrics.statsMpbs.labels(dst).set(data.stats.mbps);
                metrics.la1.labels(dst).set(data.la1);
                // ... Update other stats metrics ...

                // Update IAT Metrics
                metrics.iat1Min.labels(dst).set(data.stats.iat1_min);
                metrics.iat1Max.labels(dst).set(data.stats.iat1_max);
                metrics.iat1Avg.labels(dst).set(data.stats.iat1_avg);
        
                // Handle Services Metrics
                // Check if services is defined and is an array
                if (Array.isArray(data.services)) {
                    data.services.forEach((service, index) => {
                        // Update metrics related to services
                        serviceStreamCount.labels(dst, index.toString()).set(service.streams.length);
                        // Additional metrics for services can be handled here
                    });
                } else {
                    console.error('Invalid or missing services:', data.services);
                }
    
            } catch (e) {
                console.error(`Failed to process message: ${message.value.toString()}`, e);
            }
        },
    });    
};

// Utility Functions
function isJson(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}

// Metrics Endpoint for Prometheus
app.get('/metrics', async (req, res) => {
    try {
        res.set('Content-Type', promClient.register.contentType);
        const metrics = await promClient.register.metrics();
        res.end(metrics);
    } catch (error) {
        console.error('Failed to retrieve metrics:', error);
        res.status(500).end('Internal server error');
    }
});

app.listen(3002);

run().catch(console.error);