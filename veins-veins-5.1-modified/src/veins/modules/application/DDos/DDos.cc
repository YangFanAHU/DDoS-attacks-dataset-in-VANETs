/*
 * DDos.cc
 *
 *  Created on: 2021��9��27��
 *      Author: YF
 */

#include "veins/modules/application/DDos/DDos.h"
#include "veins/rapidjson/writer.h"
#include "veins/rapidjson/stringbuffer.h"


using namespace veins;
using namespace rapidjson;

Define_Module(veins::DDos);

void DDos::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0)
    {
        time_window = par ("time_window");
        time_window_floor = 0;
        received_packets = 0;
        received_addresses = 0;
        max_pkt_from_sameId = 0;
        has_attacker = 0;
        addresses_stack = (LAddress::L2Type*)malloc(sizeof(LAddress::L2Type));
        pktnum_stack = (int*)malloc(sizeof(int));
        prepkt_time = 0;
        lastpkt_time = 0;
        IAT_Mean = 0;
        IAT_Std = 0;
        IAT_Max = 0;
        IAT_Min = 65535;
        IAT_stack = (double*)malloc(sizeof(double));
        seed = par ("seed").doubleValue();
        attack_pausibility = par ("attack_pausibility").doubleValue();
        is_attacker = 0;
        starttime = par ("starttime").doubleValue();
        ddostype = par ("DDosType");
        DDosInterval = par ("DDosInterval").doubleValue();
        newInterval = DDosInterval;
        IncreasingType = par ("IncreasingType").doubleValue();
        IncreasingRate = par ("IncreasingRate").doubleValue();
        Increaseingthreshold = par ("Increaseingthreshold").doubleValue();
        msgtype = par ("MsgType");
        attackerSpeedRangeMin = par ("attackerSpeedRangeMin").doubleValue();
        attackerSpeedRangeMax = par ("attackerSpeedRangeMax").doubleValue();
    }
    else if (stage ==1)
    {
        DDostype_in_BSM = 0;
        Msgtype_in_BSM = 0;
        senderAddress = myId;
        if (simTime() <= starttime)
        {
        is_attacker = (dblrand() <= std::abs(attack_pausibility));
        EV<<"is attacker? : "<<is_attacker<<endl;


        if(is_attacker && (ddostype == 3 || ddostype == 4)){   //Fluctuation rate
            num_of_groups = par ("num_of_groups");
            group = intrand(myId)%3;
            duration = par ("duration").doubleValue();

            EV<<"My group: "<<group<<endl;

            if (group == 0){
                key = ON;
                timeleft = duration;
            }
            else{
                key = OFF;
                if (ddostype == 3)
                    timeleft = duration * group;
                else
                    timeleft = 0.5 * duration * group;
            }
            synchronous = false;
        }
        }

//****************************************************************
        std::ostringstream out_json1;
        out_json1 << "Dataset_pktsum.json";
        traceJSONFile_1 = out_json1.str();
        std::ostringstream out_json2;
        out_json2 << "Dataset_timewinsum.json";
        traceJSONFile_2 = out_json2.str();
        std::ostringstream out_json3;
        out_json3 << "Dataset_truth.json";
        traceJSONFile_3 = out_json3.str();
        std::ostringstream out_json4;
        out_json4 << "Dataset_pkt_"<<myId<<".json";
        traceJSONFile_4 = out_json4.str();
        std::ostringstream out_json5;
        out_json5 << "Dataset_timewin_"<<myId<<".json";
        traceJSONFile_5 = out_json5.str();
//****************************************************************
    }
}

void DDos::handleSelfMsg(cMessage* msg)
{
    if (is_attacker == 1 && starttime <= simTime())
    {
        switch (msg->getKind()) {
            case SEND_BEACON_EVT: {
                DDosMessage* ddos = new DDosMessage();
                RecordTrueData(ddos);
                switch (msgtype) {
                case 0://normal
                {
                    Msgtype_in_BSM = 0;
                    break;
                }
                case 1://Speed
                {
                    Msgtype_in_BSM = 1;
                    SetRandomDynamicSpeed();
                    break;
                }
                case 2://Position
                {
                    Msgtype_in_BSM = 2;
                    SetRandomDynamicPosition();
                    break;
                }
                case 3://Heading
                {
                    Msgtype_in_BSM = 3;
                    SetRandomDynamicHeading();
                    break;
                }
                case 4://Mix
                {
                    Msgtype_in_BSM = intrand(4);
                    switch (Msgtype_in_BSM) {
                    case 0:
                    {
                        break;
                    }
                    case 1:
                    {
                        SetRandomDynamicSpeed();
                        break;
                    }
                    case 2:
                    {
                        SetRandomDynamicPosition();
                        break;
                    }
                    case 3:
                    {
                        SetRandomDynamicHeading();
                        break;
                    }
                    }
                }
/*                case 4://Acceleration
                {
                    Msgtype_in_BSM = 4;
                    SetRandomDynamicAcceleration();
                    break;
                }*/
                }
                switch (ddostype)
                {
                case 0://Normal
                {
                    DDostype_in_BSM = 0;
                    break;
                }
                case 1://Constant rate
                {
                    DDostype_in_BSM = 1;
                    ConstantRate(ddos);
                    break;
                }
                case 2://Increasing rate
                {
                    DDostype_in_BSM = 2;
                    switch (IncreasingType){
                    case 1:
                    {
                        IncreasingRate1(ddos);
                        break;
                    }
                    case 2:
                    {
                        IncreasingRate2(ddos);
                        break;
                    }
                    }
                    break;
                }
                case 3://On-Off
                {
                    DDostype_in_BSM = 3;
                    if (synchronous == false)
                    {
                        timeleft = timeleft - (simTime() - starttime);
                        synchronous = true;
                    }
                    PulseAttack(ddos);
                    break;
                }
                case 4://Increacing On-Off
                {
                    DDostype_in_BSM = 4;
                    if (synchronous == false)
                    {
                        timeleft = timeleft - (simTime() - starttime);
                        synchronous = true;
                    }
                    Increasing_Pulse(ddos);
                    break;
                }
                }
                break;
            }
            case SEND_WSA_EVT: {
                DemoServiceAdvertisement* wsa = new DemoServiceAdvertisement();
                DemoBaseApplLayer::populateWSM(wsa);
                sendDown(wsa);
                scheduleAt(simTime() + wsaInterval, sendWSAEvt);
                break;
            }
            default: {
                if (msg) EV_WARN << "APP: Error: Got Self Message of unknown kind! Name: " << msg->getName() << endl;
                break;
            }
        }
    }
    else{
        switch (msg->getKind()) {
            case SEND_BEACON_EVT: {
                DDostype_in_BSM = 0;
                Msgtype_in_BSM = 0;
                DDosMessage* bsm = new DDosMessage();
                RecordTrueData(bsm);
                populateWSM(bsm);
                sendDown(bsm);
                scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
                break;
            }
            case SEND_WSA_EVT: {
                DemoServiceAdvertisement* wsa = new DemoServiceAdvertisement();
                DemoBaseApplLayer::populateWSM(wsa);
                sendDown(wsa);
                scheduleAt(simTime() + wsaInterval, sendWSAEvt);
                break;
            }
            default: {
                if (msg) EV_WARN << "APP: Error: Got Self Message of unknown kind! Name: " << msg->getName() << endl;
                break;
            }
        }
    }
}

void DDos::SetRandomDynamicSpeed()
{
    Coord randomSpeedInRange = Coord(uniform(attackerSpeedRangeMin, attackerSpeedRangeMax), uniform(attackerSpeedRangeMin, attackerSpeedRangeMax));
    double newXSpeed = curSpeed.x + randomSpeedInRange.x;
    double newYSpeed = curSpeed.y + randomSpeedInRange.y;
    curSpeed = Coord(newXSpeed, newYSpeed, curSpeed.z);
}

void DDos::SetRandomDynamicPosition()
{
    Coord randomPositionInRange = Coord(uniform(attackerPosRangeMin, attackerPosRangeMax), uniform(attackerPosRangeMin, attackerPosRangeMax));
    double newXPos = curPosition.x + randomPositionInRange.x;
    double newYPos = curPosition.y + randomPositionInRange.y;
    curPosition = Coord(newXPos, newYPos, curPosition.z);
}

/*void DDos::SetRandomDynamicAcceleration()
{
    double randomAccelerationInRange = uniform(attackerAcclRangeMin, attackerAcclRangeMax);
    Acceleration = Acceleration + randomAccelerationInRange;
}*/

void DDos::SetRandomDynamicHeading()
{
    double randomHeadingInRange = uniform(attackerHeadRangeMin, attackerHeadRangeMax);
    double newRad = heading.getRad()+randomHeadingInRange;
    heading = Heading(newRad);
    EV<<"heading = "<<heading<<endl;
    Coord coord = heading.toCoord();
    Heading newHd = heading.fromCoord(coord);
    heading = Heading(newHd);
    EV<<"new hed = "<<heading<<endl;
}

void DDos::ConstantRate(DDosMessage* ddos)
{
    populateWSM(ddos);
    sendDown(ddos);
    scheduleAt(simTime() + DDosInterval*0.95 + DDosInterval*0.01*intrand(10), sendBeaconEvt);
}

void DDos::IncreasingRate1(DDosMessage* ddos)
{
    populateWSM(ddos);
    sendDown(ddos);
    scheduleAt(simTime() + newInterval, sendBeaconEvt);
    if (newInterval > Increaseingthreshold)
        newInterval = newInterval*IncreasingRate;
}

void DDos::IncreasingRate2(DDosMessage* ddos)
{
    populateWSM(ddos);
    sendDown(ddos);
    scheduleAt(simTime() + newInterval, sendBeaconEvt);
    if (newInterval > Increaseingthreshold)
    {
        double u=0;
        u = uniform(0.0001, 0.002);
        if (newInterval - u >=0.001)
            newInterval = newInterval-u;
    }
}

void DDos::PulseAttack(DDosMessage* ddos)
{
    switch (key) {
    case ON: {
        populateWSM(ddos);
        sendDown(ddos);
        if (timeleft > DDosInterval)
        {
            scheduleAt(simTime() + DDosInterval, sendBeaconEvt);
            timeleft = timeleft - DDosInterval;
        }
        else if (timeleft > 0)
        {
            key = OFF;
            scheduleAt(simTime() + timeleft, sendBeaconEvt);
            timeleft = duration*(num_of_groups-1);
        }
        else{
            key = OFF;
            scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
            timeleft = duration*(num_of_groups-1);
            timeleft = timeleft - beaconInterval;
        }
        break;
    }
    case OFF: {
        DDostype_in_BSM = 0;
        populateWSM(ddos);
        sendDown(ddos);
        if (timeleft >= beaconInterval)
        {
            scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
            timeleft = timeleft - beaconInterval;
        }
        else if (timeleft > 0)
        {
            key = ON;
            scheduleAt(simTime() + timeleft, sendBeaconEvt);
            timeleft = duration;
        }
        else{
            key = ON;
            scheduleAt(simTime() + DDosInterval, sendBeaconEvt);
            timeleft = duration;
        }
        break;
    }
    }
}
void DDos::Increasing_Pulse(DDosMessage* ddos)
{
    switch (key) {
    case ON: {
        populateWSM(ddos);
        sendDown(ddos);
        if (timeleft > newInterval)
        {
            scheduleAt(simTime() + newInterval, sendBeaconEvt);
            timeleft = timeleft - newInterval;
            if (newInterval > Increaseingthreshold)
            newInterval = newInterval * IncreasingRate;
        }
        else if (timeleft > 0)
        {
            key = OFF;
            scheduleAt(simTime() + timeleft, sendBeaconEvt);
            timeleft = duration*(num_of_groups-2)/2;
            newInterval = DDosInterval;
        }
        else{
            key = OFF;
            scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
            timeleft = duration*(num_of_groups-2)/2;
            timeleft = timeleft - beaconInterval;
            newInterval = DDosInterval;
        }
        break;
    }
    case OFF: {
        DDostype_in_BSM = 0;
        populateWSM(ddos);
        sendDown(ddos);
        if (timeleft >= beaconInterval)
        {
            scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
            timeleft = timeleft - beaconInterval;
        }
        else if (timeleft > 0)
        {
            key = ON;
            scheduleAt(simTime() + timeleft, sendBeaconEvt);
            timeleft = duration;
        }
        else
        {
            key = ON;
            scheduleAt(simTime() + newInterval, sendBeaconEvt);
            timeleft = duration;
            newInterval = newInterval * IncreasingRate;
        }
        break;
    }
    }
}

void DDos::populateWSM(BaseFrame1609_4* wsm, LAddress::L2Type rcvId, int serial)
{
    wsm->setRecipientAddress(rcvId);
    wsm->setBitLength(headerLength);

    if (DDosMessage* ddos = dynamic_cast<DDosMessage*>(wsm)) {
       ddos->setTimestamp(simTime());
       ddos->setSenderAddress(myId);
       ddos->setSenderPos(curPosition);
       ddos->setSenderSpeed(curSpeed);
       ddos->setHeading(heading);
//       ddos->setAcceleration(Acceleration);
       ddos->setDDostype(DDostype_in_BSM);
       ddos->setMsgtype(Msgtype_in_BSM);
       ddos->setPsid(-1);
       ddos->setChannelNumber(static_cast<int>(Channel::cch));
       ddos->addBitLength(beaconLengthBits);
       wsm->setUserPriority(beaconUserPriority);

//***************************************************
       Coord pos = ddos->getSenderPos();
       Coord spd = ddos->getSenderSpeed();
       StringBuffer s;
       Writer<StringBuffer> writer(s);

       writer.StartObject();

       writer.Key("time");
       writer.Double(simTime().dbl());
       writer.Key("senderID");
       writer.Uint(ddos->getSenderAddress());
       writer.Key("messageID");
       writer.Uint(ddos->getId());
       writer.Key("position");
       writer.StartArray();
       writer.Double(pos.x);
       writer.Double(pos.y);
       writer.Double(pos.z);
       writer.EndArray();

       writer.Key("speed");
       writer.StartArray();
       writer.Double(spd.x);
       writer.Double(spd.y);
       writer.Double(spd.z);
       writer.EndArray();

       writer.Key("heading");
       writer.Double(heading.getRad());

//       writer.Key("acceleration");
//       writer.Double(Acceleration);

       writer.Key("ddostype");
       writer.Int(ddos->getDDostype());
       writer.Key("msgtype");
       writer.Int(ddos->getMsgtype());


       writer.EndObject();

       traceJSON(traceJSONFile_1, s.GetString());
//***************************************************************
   }
}

void DDos::RecordTrueData(DDosMessage* ddos)
{
    Coord pos = curPosition;
    Coord spd = curSpeed;
    StringBuffer s;
    Writer<StringBuffer> writer(s);

    writer.StartObject();

    writer.Key("senderID");
    writer.Uint(myId);
    writer.Key("messageID");
    writer.Uint(ddos->getId());
    writer.Key("position");
    writer.StartArray();
    writer.Double(pos.x);
    writer.Double(pos.y);
    writer.Double(pos.z);
    writer.EndArray();

    writer.Key("speed");
    writer.StartArray();
    writer.Double(spd.x);
    writer.Double(spd.y);
    writer.Double(spd.z);
    writer.EndArray();

    writer.Key("heading");
    writer.Double(heading.getRad());

//    writer.Key("acceleration");
//    writer.Double(Acceleration);



    writer.EndObject();

    traceJSON(traceJSONFile_3, s.GetString());
}

void DDos::handlePositionUpdate(cObject* obj)
{
    heading = mobility->getHeading();
//    Acceleration = mobility->getAcceleration();
    ChannelMobilityPtrType const mobility = check_and_cast<ChannelMobilityPtrType>(obj);
    curPosition = mobility->getPositionAt(simTime());
    curSpeed = mobility->getCurrentSpeed();
//    EV<<"CurSpeed = "<<curSpeed<<endl;
//    heading = mobility->getCurrentOrientation();
//    EV<<"Heading = "<<heading<<endl;
//    EV<<"Acceleration = "<<Acceleration<<endl;
}

void DDos::handleLowerMsg(cMessage* msg)
{

    BaseFrame1609_4* wsm = dynamic_cast<BaseFrame1609_4*>(msg);
    ASSERT(wsm);

    if (DDosMessage* ddos = dynamic_cast<DDosMessage*>(wsm)) {
        receivedBSMs++;
        onDDos(ddos);
    }
    else if (DemoSafetyMessage* bsm = dynamic_cast<DemoSafetyMessage*>(wsm)) {
        receivedBSMs++;
        onBSM(bsm);
    }
    else if (DemoServiceAdvertisement* wsa = dynamic_cast<DemoServiceAdvertisement*>(wsm)) {
        receivedWSAs++;
        onWSA(wsa);
    }
    else {
        receivedWSMs++;
        onWSM(wsm);
    }

    delete (msg);
}

void DDos::onDDos(DDosMessage* ddos)
{
    Coord pos = ddos->getSenderPos();
    Coord spd = ddos->getSenderSpeed();
    StringBuffer s;
    Writer<StringBuffer> writer(s);

    writer.StartObject();

    writer.Key("sendtime");
    writer.Double(ddos->getTimestamp().dbl());
    writer.Key("rcvtime");
    writer.Double(simTime().dbl());
    writer.Key("senderID");
    writer.Uint(ddos->getSenderAddress());
    writer.Key("messageID");
    writer.Uint(ddos->getId());
    writer.Key("position");
    writer.StartArray();
    writer.Double(pos.x);
    writer.Double(pos.y);
    writer.Double(pos.z);
    writer.EndArray();

    writer.Key("speed");
    writer.StartArray();
    writer.Double(spd.x);
    writer.Double(spd.y);
    writer.Double(spd.z);
    writer.EndArray();

    writer.Key("heading");
    writer.Double(heading.getRad());

//    writer.Key("acceleration");
//    writer.Double(Acceleration);

    writer.Key("ddostype");
    writer.Int(ddos->getDDostype());
    writer.Key("msgtype");
    writer.Int(ddos->getMsgtype());



    writer.EndObject();

    traceJSON(traceJSONFile_4, s.GetString());

    if ( simTime() <= time_window_floor + time_window)
    {
        if (ddos->getDDostype()!=0 || ddos->getMsgtype()!=0)
            has_attacker = 1;
        received_packets++;

        prepkt_time = lastpkt_time;
        lastpkt_time = simTime().dbl();
        IAT_stack = (double*)realloc(IAT_stack,received_packets*sizeof(double));
        IAT_stack[received_packets-1] = lastpkt_time - prepkt_time;
        IAT_Mean = IAT_Mean + IAT_stack[received_packets-1];
        if (IAT_stack[received_packets-1] > IAT_Max)
            IAT_Max = IAT_stack[received_packets-1];
        if (IAT_stack[received_packets-1] < IAT_Min)
            IAT_Min = IAT_stack[received_packets-1];

        int i = 0;
        for (i=0 ; i<received_addresses ; i++)
            if( ddos->getSenderAddress() == addresses_stack[i] )
            {
                pktnum_stack[i]++;
                if(pktnum_stack[i] > max_pkt_from_sameId)
                    max_pkt_from_sameId = pktnum_stack[i];
                break;
            }

        if( i == received_addresses )
        {
            received_addresses++;
            addresses_stack = (LAddress::L2Type*)realloc(addresses_stack,received_addresses*sizeof(LAddress::L2Type));
            pktnum_stack = (int*)realloc(pktnum_stack,received_addresses*sizeof(int));
            addresses_stack[received_addresses-1] = ddos->getSenderAddress();

            if (ddos->getDDostype()!=0 || ddos->getMsgtype()!=0)
                has_attacker = 1;
            pktnum_stack[received_addresses-1] = 1;
            if( max_pkt_from_sameId == 0)
                max_pkt_from_sameId = 1;
        }
    }
    else
    {
        if (received_packets != 0 && received_packets != 1){
        IAT_Mean = IAT_Mean/received_packets;

        for (int i = 0 ; i < received_packets; i++)
            IAT_Std = IAT_Std + pow(IAT_Mean - IAT_stack[i],2);
        IAT_Std = sqrt(IAT_Std/received_packets);

        StringBuffer s;
        Writer<StringBuffer> writer(s);

        writer.StartObject();


        writer.Key("received packets");
        writer.Int(received_packets);
        writer.Key("IAT_Mean");
        writer.Double(IAT_Mean);
        writer.Key("IAT_Std");
        writer.Double(IAT_Std);
        writer.Key("IAT_Max");
        writer.Double(IAT_Max);
        writer.Key("IAT_Min");
        writer.Double(IAT_Min);
        writer.Key("received_addresses");
        writer.Int(received_addresses);
        writer.Key("max_pkt_from_sameId");
        writer.Int(max_pkt_from_sameId);
        writer.Key("has_attacker");
        writer.Int(has_attacker);

        writer.EndObject();

        traceJSON(traceJSONFile_2, s.GetString());
        traceJSON(traceJSONFile_5, s.GetString());
        }
        else if (received_packets == 1)
        {
            IAT_Mean = 2;
            IAT_Std = 0;
            IAT_Max = 2;
            IAT_Min = 2;
            StringBuffer s;
            Writer<StringBuffer> writer(s);

            writer.StartObject();


            writer.Key("received packets");
            writer.Int(received_packets);
            writer.Key("IAT_Mean");
            writer.Double(IAT_Mean);
            writer.Key("IAT_Std");
            writer.Double(IAT_Std);
            writer.Key("IAT_Max");
            writer.Double(IAT_Max);
            writer.Key("IAT_Min");
            writer.Double(IAT_Min);
            writer.Key("received_addresses");
            writer.Int(received_addresses);
            writer.Key("max_pkt_from_sameId");
            writer.Int(max_pkt_from_sameId);
            writer.Key("has_attacker");
            writer.Int(has_attacker);

            writer.EndObject();

            traceJSON(traceJSONFile_2, s.GetString());
            traceJSON(traceJSONFile_5, s.GetString());
        }
        time_window_floor = time_window_floor + (int)time_window*(((int)floor(simTime().dbl())-(int)time_window_floor)/(int)time_window);

        received_packets = 1;
        received_addresses =1;
        max_pkt_from_sameId = 1;
        free(addresses_stack);
        free(pktnum_stack);

        free(IAT_stack);

        addresses_stack = (LAddress::L2Type*)malloc(sizeof(LAddress::L2Type));
        pktnum_stack = (int*)malloc(sizeof(int));

        addresses_stack[received_addresses-1] = ddos->getSenderAddress();
        pktnum_stack[received_addresses-1] = 1;

        has_attacker = 0;

        if (ddos->getDDostype()!=0 || ddos->getMsgtype()!=0)
            has_attacker = 1;

        prepkt_time = time_window_floor;
        lastpkt_time = simTime().dbl();
        IAT_stack = (double*)malloc(sizeof(double));
        IAT_stack[received_packets-1] = lastpkt_time - prepkt_time;

        IAT_Mean = IAT_stack[received_packets-1];
        IAT_Std = 0;
        IAT_Max = IAT_stack[received_packets-1];
        IAT_Min = IAT_stack[received_packets-1];
    }
}

const void DDos::traceJSON(std::string file, std::string JSONObject) const {
    std::ofstream out_stream;
    out_stream.open(file, std::ios_base::app);
    if(out_stream.is_open())
        out_stream << JSONObject << std::endl;
    else
        EV << "Warning, tracing stream is closed";
    out_stream.close();
}




