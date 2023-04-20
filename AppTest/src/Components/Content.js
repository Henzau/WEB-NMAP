import '../styles/Content.css';
import { useState } from 'react'
import Listening from './Listening';
import Home from './Home';
import Url from './UrlComponent'
import Prediction from './Prediction';


function Content({selectedModel,isContent,setIsContent}) {
  
  const [isReceiving, setIsReceiving] = useState(false)
  const [isListening, setIsListening] = useState(false)
  const [data, setdata] = useState({});
  const [isDisplay, setIsDisplay] = useState(false);
  const [id, setid] = useState({});


  function renderSwitch(param) {
    switch(param) {
      case 0:
        return <Home selectedModel={selectedModel.value} data={data} setdata={setdata} isDisplay={isDisplay} setIsDisplay={setIsDisplay} id={id} setid={setid} setIsContent={setIsContent} isListening={isListening} setIsListening={setIsListening} isReceiving={isReceiving} setIsReceiving={setIsReceiving}/>;
      case 1:
        return <Url selectedModel={selectedModel.value} />;
      case 2:
        return <Listening selectedModel={selectedModel.value} isDisplay={isDisplay} setIsDisplay={setIsDisplay} setdata={setdata} id={id} setIsContent={setIsContent} isReceiving={isReceiving} setIsReceiving={setIsReceiving} setIsListening={setIsListening}/>;
      case 3:
        return <Prediction selectedModel={selectedModel.value} isDisplay={isDisplay} setIsDisplay={setIsDisplay} data={data} />;
      default:
        return  <div>
                </div>;
    }
  }

    

  return(
    <div className="Content">
      {renderSwitch(isContent)}
    </div>
  );
}

export default Content;
